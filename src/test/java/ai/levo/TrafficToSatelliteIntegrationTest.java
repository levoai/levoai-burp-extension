package ai.levo;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Runs a captured message through the real listener, publisher, and Satellite
 * client. Burp's API jar is interfaces only, so the helpers fake the documented
 * byte-to-character mapping and header parse. CI executes this with {@code ./gradlew test}.
 */
class TrafficToSatelliteIntegrationTest {

    private static final String ORG = "123e4567-e89b-12d3-a456-426614174000";
    private static final ObjectMapper JSON = new ObjectMapper();

    private HttpServer server;
    private final AtomicInteger posts = new AtomicInteger();
    private final AtomicReference<String> postedBody = new AtomicReference<>();
    private final AtomicReference<String> postedOrg = new AtomicReference<>();
    private final AtomicReference<String> postedPath = new AtomicReference<>();
    private CountDownLatch posted;

    private IBurpExtenderCallbacks callbacks;
    private final List<String> output = new CopyOnWriteArrayList<>();
    private HttpMessagePublisher publisher;
    private HttpMessageListener listener;

    @BeforeEach
    void setUp() throws IOException {
        posted = new CountDownLatch(1);
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/1.0/ebpf/traces", exchange -> {
            posts.incrementAndGet();
            postedPath.set(exchange.getRequestURI().getPath());
            postedOrg.set(exchange.getRequestHeaders().getFirst("x-levo-organization-id"));
            postedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
            posted.countDown();
        });
        server.start();

        callbacks = mock(IBurpExtenderCallbacks.class);
        IExtensionHelpers helpers = mock(IExtensionHelpers.class);
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(callbacks.getToolName(IBurpExtenderCallbacks.TOOL_SPIDER)).thenReturn("Spider");
        when(callbacks.getToolName(IBurpExtenderCallbacks.TOOL_PROXY)).thenReturn("Proxy");
        when(callbacks.getToolName(IBurpExtenderCallbacks.TOOL_SCANNER)).thenReturn("Scanner");
        doAnswer(invocation -> {
            output.add(invocation.getArgument(0));
            return null;
        }).when(callbacks).printOutput(anyString());
        when(helpers.base64Encode(any(byte[].class))).thenAnswer(invocation ->
                Base64.getEncoder().encodeToString(invocation.getArgument(0)));
        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenAnswer(invocation -> {
            IHttpRequestResponse message = invocation.getArgument(0);
            return requestInfo(message.getRequest());
        });
        when(helpers.analyzeResponse(any(byte[].class))).thenAnswer(invocation ->
                responseInfo(invocation.getArgument(0)));

        int port = server.getAddress().getPort();
        LevoSatelliteService satellite = new LevoSatelliteService(
                "http://127.0.0.1:" + port + "/ignored", ORG, "qa");
        AlertWriter alerts = new AlertWriter(callbacks);
        publisher = new HttpMessagePublisher(satellite, alerts, callbacks);
        listener = new HttpMessageListener(publisher, alerts, callbacks);
        ConfigMenu.IS_SENDING_ENABLED = true;
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;
    }

    @AfterEach
    void tearDown() {
        ConfigMenu.IS_SENDING_ENABLED = false;
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;
        if (publisher != null) {
            publisher.extensionUnloaded();
        }
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void spiderJsonExchange_isPostedToSatelliteIntact() throws Exception {
        String requestBody = "{\"sku\":\"abc\"}";
        String responseBody = "{\"data\":{\"id\":\"1\"}}";
        byte[] request = request(
                "POST /api/orders?dryRun=1 HTTP/1.1",
                "Host: shop.example",
                "Content-Type: Application/JSON; charset=UTF-8",
                "",
                requestBody);
        byte[] response = request(
                "HTTP/1.1 201 Created",
                "Content-Type: application/vnd.api+json",
                "",
                responseBody);

        listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_SPIDER, false, message(request, response));

        assertTrue(posted.await(5, TimeUnit.SECONDS), "Satellite did not receive the trace");
        assertEquals("/1.0/ebpf/traces", postedPath.get());
        assertEquals(ORG, postedOrg.get());

        JsonNode trace = JSON.readTree(postedBody.get());
        assertEquals("qa", trace.path("resource").path("levo_env").asText());
        assertEquals("BURP_EXTENSION", trace.path("resource").path("sensor_type").asText());
        assertEquals("SERVER", trace.path("span_kind").asText());
        assertEquals("POST", trace.path("request").path("headers").path(":method").asText());
        assertEquals("/api/orders?dryRun=1", trace.path("request").path("headers").path(":path").asText());
        assertEquals("Application/JSON; charset=UTF-8",
                trace.path("request").path("headers").path("content-type").asText());
        assertEquals(requestBody, new String(Base64.getDecoder().decode(
                trace.path("request").path("body").asText()), StandardCharsets.UTF_8));
        assertEquals("201", trace.path("response").path("headers").path(":status").asText());
        assertEquals("application/vnd.api+json",
                trace.path("response").path("headers").path("content-type").asText());
        assertEquals(responseBody, new String(Base64.getDecoder().decode(
                trace.path("response").path("body").asText()), StandardCharsets.UTF_8));
        assertTrue(outputEventuallyContains("Sent the HTTP message for: shop.example/api/orders"));
    }

    @Test
    void xmlRequestAndGrpcResponse_keepBytesPastABlankLine() throws Exception {
        byte[] request = request(
                "POST /soap HTTP/1.1",
                "Host: shop.example",
                "Content-Type: text/xml",
                "",
                "<a>",
                "",
                "<b>1</b></a>");
        byte[] grpc = new byte[] {0x00, 0x00, 0x00, 0x00, 0x05, 0x0d, 0x0a, 0x0d, 0x0a, (byte) 0xff};
        byte[] response = concat(request(
                "HTTP/1.1 200 OK",
                "Content-Type: application/grpc",
                "",
                ""), grpc);

        listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, false, message(request, response));

        assertTrue(posted.await(5, TimeUnit.SECONDS), "Satellite did not receive the trace");
        JsonNode trace = JSON.readTree(postedBody.get());
        assertEquals("<a>\r\n\r\n<b>1</b></a>", new String(Base64.getDecoder().decode(
                trace.path("request").path("body").asText()), StandardCharsets.ISO_8859_1));
        assertArrayEquals(grpc, Base64.getDecoder().decode(trace.path("response").path("body").asText()));
        assertFalse(trace.path("request").path("truncated").asBoolean());
        assertFalse(trace.path("response").path("truncated").asBoolean());
    }

    @Test
    void htmlResponse_isNotPosted() throws Exception {
        byte[] request = request("GET / HTTP/1.1", "Host: www.google.com", "", "");
        byte[] response = request(
                "HTTP/1.1 200 OK",
                "Content-Type: text/html; charset=UTF-8",
                "",
                "<html></html>");

        listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, false, message(request, response));
        drainPublisher();

        assertEquals(0, posts.get());
        assertTrue(output.stream().anyMatch(line ->
                line.contains("response content-type 'text/html; charset=UTF-8' is not instrumented")));
    }

    @Test
    void scannerTraffic_isNotPosted() throws Exception {
        byte[] request = request(
                "POST /api HTTP/1.1",
                "Host: shop.example",
                "Content-Type: application/json",
                "",
                "{}");
        byte[] response = request("HTTP/1.1 200 OK", "Content-Type: application/json", "", "{}");

        listener.processHttpMessage(IBurpExtenderCallbacks.TOOL_SCANNER, false, message(request, response));
        drainPublisher();

        assertEquals(0, posts.get());
    }

    @Test
    void sendToLevoMenu_postsSupportedMessageAndReportsTheOther() throws Exception {
        byte[] htmlRequest = request("GET / HTTP/1.1", "Host: www.google.com", "", "");
        byte[] htmlResponse = request("HTTP/1.1 200 OK", "Content-Type: text/html", "", "<html></html>");
        byte[] jsonRequest = request(
                "POST /api/orders HTTP/1.1",
                "Host: shop.example",
                "Content-Type: application/json",
                "",
                "{\"sku\":\"abc\"}");
        byte[] jsonResponse = request("HTTP/1.1 200 OK", "Content-Type: application/json", "", "{\"ok\":true}");

        List<String> notices = new ArrayList<>();
        new SendToLevoMenu(callbacks, publisher).sendSelected(new IHttpRequestResponse[]{
                message(htmlRequest, htmlResponse),
                message(jsonRequest, jsonResponse)
        }, notices::add);

        assertTrue(posted.await(5, TimeUnit.SECONDS));
        assertEquals(1, posts.get());
        JsonNode trace = JSON.readTree(postedBody.get());
        assertEquals("/api/orders", trace.path("request").path("headers").path(":path").asText());
        assertEquals("{\"sku\":\"abc\"}", new String(Base64.getDecoder().decode(
                trace.path("request").path("body").asText()), StandardCharsets.UTF_8));
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).contains("text/html"));
        assertTrue(notices.get(0).contains("Queued 1 other message."));
    }

    private boolean outputEventuallyContains(String text) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline) {
            if (output.stream().anyMatch(line -> line.contains(text))) {
                return true;
            }
            Thread.sleep(20);
        }
        return output.stream().anyMatch(line -> line.contains(text));
    }

    private void drainPublisher() throws InterruptedException {
        publisher.getPublishExecutor().shutdown();
        assertTrue(publisher.getPublishExecutor().awaitTermination(5, TimeUnit.SECONDS));
        publisher = null;
    }

    private static IHttpRequestResponse message(byte[] request, byte[] response) {
        IHttpRequestResponse message = mock(IHttpRequestResponse.class);
        when(message.getRequest()).thenReturn(request);
        when(message.getResponse()).thenReturn(response);
        return message;
    }

    private static byte[] request(String... lines) {
        return String.join("\r\n", lines).getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] concat(byte[] head, byte[] tail) {
        byte[] out = new byte[head.length + tail.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(tail, 0, out, head.length, tail.length);
        return out;
    }

    private static String latin1(byte[] data) {
        char[] chars = new char[data.length];
        for (int i = 0; i < data.length; i++) {
            chars[i] = (char) (data[i] & 0xff);
        }
        return new String(chars);
    }

    private static IRequestInfo requestInfo(byte[] raw) throws Exception {
        List<String> lines = headerLines(raw);
        String[] requestLine = lines.get(0).split(" ");
        String target = requestLine[1];
        String host = headerValue(lines, "host");
        URL url = new URL("http://" + host + target);
        IRequestInfo info = mock(IRequestInfo.class);
        when(info.getHeaders()).thenReturn(lines);
        when(info.getMethod()).thenReturn(requestLine[0]);
        when(info.getUrl()).thenReturn(url);
        when(info.getBodyOffset()).thenReturn(bodyOffset(raw));
        return info;
    }

    private static IResponseInfo responseInfo(byte[] raw) {
        List<String> lines = headerLines(raw);
        int status = Integer.parseInt(lines.get(0).split(" ")[1]);
        IResponseInfo info = mock(IResponseInfo.class);
        when(info.getHeaders()).thenReturn(lines);
        when(info.getStatusCode()).thenReturn((short) status);
        when(info.getBodyOffset()).thenReturn(bodyOffset(raw));
        return info;
    }

    private static int bodyOffset(byte[] raw) {
        for (int i = 0; i + 3 < raw.length; i++) {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                return i + 4;
            }
        }
        return raw.length;
    }

    private static List<String> headerLines(byte[] raw) {
        String message = latin1(raw);
        int split = message.indexOf("\r\n\r\n");
        String head = split >= 0 ? message.substring(0, split) : message;
        return Collections.unmodifiableList(Arrays.asList(head.split("\r\n")));
    }

    private static String headerValue(List<String> lines, String name) {
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return "";
    }
}
