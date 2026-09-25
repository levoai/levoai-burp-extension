package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import javax.net.ssl.SSLHandshakeException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class LevoSatelliteServiceHttpTest {

    private static final String ORG = "123e4567-e89b-12d3-a456-426614174000";

    @Test
    void sendHttpMessage_postsDirectlyToTracesPath() throws Exception {
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> org = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/1.0/ebpf/traces", exchange -> {
            method.set(exchange.getRequestMethod());
            path.set(exchange.getRequestURI().getPath());
            org.set(exchange.getRequestHeaders().getFirst("x-levo-organization-id"));
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            LevoSatelliteService service = new LevoSatelliteService(
                    "http://127.0.0.1:" + port + "/ignored", ORG, "staging");
            HttpMessage message = new HttpMessage();
            message.setTraceId("trace-1");

            assertNull(service.sendHttpMessage(message));

            assertEquals("POST", method.get());
            assertEquals("/1.0/ebpf/traces", path.get());
            assertEquals(ORG, org.get());
            assertEquals("application/json", contentType.get());
            assertTrue(body.get().contains("trace-1"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sendHttpMessage_nonSuccessStatusIncludesBody() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/1.0/ebpf/traces", exchange -> {
            byte[] payload = "{\"error\":\"nope\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(500, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            LevoSatelliteService service = new LevoSatelliteService(
                    "http://127.0.0.1:" + port, ORG, "staging");

            SatelliteMessageFailed thrown = assertThrows(
                    SatelliteMessageFailed.class, () -> service.sendHttpMessage(new HttpMessage()));
            assertEquals((short) 500, thrown.getStatusCode());
            assertTrue(thrown.getMessage().contains("nope"));
            assertNull(thrown.getRetryAfterMillis());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sendHttpMessage_capsErrorBodyAndHonorsRetryAfter() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/1.0/ebpf/traces", exchange -> {
            byte[] payload = "E".repeat(20_000).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Retry-After", "120");
            exchange.sendResponseHeaders(503, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            LevoSatelliteService service = new LevoSatelliteService(
                    "http://127.0.0.1:" + port, ORG, "staging");

            SatelliteMessageFailed thrown = assertThrows(
                    SatelliteMessageFailed.class, () -> service.sendHttpMessage(new HttpMessage()));
            assertEquals((short) 503, thrown.getStatusCode());
            assertTrue(thrown.getMessage().endsWith("..."));
            assertTrue(thrown.getMessage().length() < 1_200);
            assertEquals(LevoSatelliteService.MAX_RETRY_AFTER_MS, thrown.getRetryAfterMillis());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void deprecatedFactory_doesNotTouchBurpCallbacks() throws Exception {
        Method create = LevoSatelliteService.class.getMethod(
                "create", String.class, String.class, String.class, IBurpExtenderCallbacks.class);
        assertEquals(LevoSatelliteService.class, create.getReturnType());
        assertNotNull(LevoSatelliteService.class.getConstructor(
                IBurpExtenderCallbacks.class, String.class, String.class, String.class));
        Method send = LevoSatelliteService.class.getMethod("sendHttpMessage", HttpMessage.class);
        assertEquals(IHttpRequestResponse.class, send.getReturnType());

        LevoSatelliteService service = LevoSatelliteService.create(
                "http://127.0.0.1:9", ORG, "staging", mock(IBurpExtenderCallbacks.class));
        assertNotNull(service);
    }

    @Test
    void sendHttpMessage_connectionRefusedIsStatusZero() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            port = socket.getLocalPort();
        }

        LevoSatelliteService service = new LevoSatelliteService(
                "http://127.0.0.1:" + port, ORG, "staging");

        SatelliteMessageFailed thrown = assertThrows(
                SatelliteMessageFailed.class, () -> service.sendHttpMessage(new HttpMessage()));
        assertEquals((short) 0, thrown.getStatusCode());
        assertTrue(thrown.getMessage().contains("Failed to connect to Levo Satellite"));
        assertTrue(thrown.isSafeToRetry());
    }

    @Test
    void requestWasNotSent_onlyForFailuresBeforeThePostIsWritten() {
        assertTrue(LevoSatelliteService.requestWasNotSent(new ConnectException("refused")));
        assertTrue(LevoSatelliteService.requestWasNotSent(
                new IOException("wrapped", new UnknownHostException("satellite.example"))));
        assertTrue(LevoSatelliteService.requestWasNotSent(new HttpConnectTimeoutException("connect timed out")));
        assertTrue(LevoSatelliteService.requestWasNotSent(new SSLHandshakeException("handshake failed")));
        assertFalse(LevoSatelliteService.requestWasNotSent(new HttpTimeoutException("request timed out")));
        assertFalse(LevoSatelliteService.requestWasNotSent(new IOException("Connection reset")));
        assertFalse(LevoSatelliteService.requestWasNotSent(
                new IOException("reset", new HttpTimeoutException("request timed out"))));
    }

    @Test
    void tracesUri_omitsDefaultPortsAndIgnoresConfiguredPath() throws Exception {
        URI https = LevoSatelliteService.tracesUri(new URL("https://satellite.levo.ai:443/custom"));
        assertEquals("https://satellite.levo.ai/1.0/ebpf/traces", https.toString());

        URI http = LevoSatelliteService.tracesUri(new URL("http://localhost:80/custom"));
        assertEquals("http://localhost/1.0/ebpf/traces", http.toString());

        URI custom = LevoSatelliteService.tracesUri(new URL("http://localhost:9999/custom"));
        assertEquals("http://localhost:9999/1.0/ebpf/traces", custom.toString());

        URI ipv6 = LevoSatelliteService.tracesUri(new URL("http://[::1]:9999/custom"));
        assertEquals("http://[::1]:9999/1.0/ebpf/traces", ipv6.toString());
    }
}
