package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HttpMessagePublisherBodyTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private LevoSatelliteService satelliteService;

    @Mock
    private IRequestInfo requestInfo;

    @Mock
    private IResponseInfo responseInfo;

    private AlertWriter alertWriter;
    private HttpMessagePublisher publisher;

    @BeforeEach
    void setUp() throws Exception {
        alertWriter = new AlertWriter(callbacks);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks,
                millis -> { }, System::nanoTime, () -> 0);
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(satelliteService.getEnvironment()).thenReturn("test");
        when(requestInfo.getMethod()).thenReturn("POST");
        when(requestInfo.getUrl()).thenReturn(new URL("http://example.com/soap"));
        when(requestInfo.getHeaders()).thenReturn(List.of(
                "POST /soap HTTP/1.1",
                "Host: example.com",
                "Content-Type: text/xml"));
        when(helpers.base64Encode(any(byte[].class))).thenAnswer(invocation ->
                Base64.getEncoder().encodeToString(invocation.getArgument(0)));
        ConfigMenu.IS_SENDING_ENABLED = true;
    }

    @AfterEach
    void tearDown() {
        publisher.extensionUnloaded();
        ConfigMenu.IS_SENDING_ENABLED = false;
    }

    @Test
    void embeddedDelimiterAndBinaryGrpcFrame_areEncodedFromBodyOffsets() throws Exception {
        String xml = "<root>\r\n\r\n<child>1</child></root>";
        byte[] request = concat(headerBytes(
                "POST /soap HTTP/1.1",
                "Host: example.com",
                "Content-Type: text/xml"), xml.getBytes(StandardCharsets.ISO_8859_1));
        byte[] grpc = new byte[] {0x00, 0x00, 0x00, 0x00, 0x05, 0x0d, 0x0a, 0x0d, 0x0a, (byte) 0xff, 0x10};
        byte[] response = concat(headerBytes(
                "HTTP/1.1 200 OK",
                "Content-Type: application/grpc"), grpc);
        when(requestInfo.getBodyOffset()).thenReturn(headerBytes(
                "POST /soap HTTP/1.1",
                "Host: example.com",
                "Content-Type: text/xml").length);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/grpc"));
        when(responseInfo.getBodyOffset()).thenReturn(headerBytes(
                "HTTP/1.1 200 OK",
                "Content-Type: application/grpc").length);
        AtomicReference<HttpMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            return null;
        }).when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, request, "200", response, responseInfo);
        awaitExecutor();

        HttpMessage sent = captured.get();
        assertEquals(xml, new String(Base64.getDecoder().decode(sent.getRequest().getBody()), StandardCharsets.ISO_8859_1));
        assertArrayEquals(grpc, Base64.getDecoder().decode(sent.getResponse().getBody()));
        assertFalse(sent.getRequest().isTruncated());
        assertFalse(sent.getResponse().isTruncated());
    }

    @Test
    void oversizedBody_isTruncatedUnderThePortalSampleCap() throws Exception {
        byte[] raw = new byte[HttpMessagePublisher.MAX_RAW_BODY_BYTES + 40];
        Arrays.fill(raw, (byte) 'a');
        raw[raw.length - 1] = 'Z';
        byte[] response = concat(headerBytes("HTTP/1.1 200 OK", "Content-Type: text/plain"), raw);
        when(requestInfo.getHeaders()).thenReturn(List.of("POST /soap HTTP/1.1", "Host: example.com"));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain"));
        when(responseInfo.getBodyOffset()).thenReturn(headerBytes(
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain").length);
        AtomicReference<HttpMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            return null;
        }).when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", response, responseInfo);
        awaitExecutor();

        byte[] decoded = Base64.getDecoder().decode(captured.get().getResponse().getBody());
        assertEquals(HttpMessagePublisher.MAX_RAW_BODY_BYTES, decoded.length);
        assertEquals('a', decoded[decoded.length - 1]);
        assertTrue(captured.get().getResponse().isTruncated());
        assertFalse(captured.get().getRequest().isTruncated());
    }

    @Test
    void queuedBodyBudget_dropsAMessageThatWouldExceedIt() throws Exception {
        publisher.extensionUnloaded();
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks,
                millis -> { }, System::nanoTime, () -> 0);
        int huge = (int) (HttpMessagePublisher.MAX_QUEUED_BODY_BYTES / 2 + 1);
        when(helpers.base64Encode(any(byte[].class))).thenReturn("x".repeat(huge));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/json"));
        when(responseInfo.getBodyOffset()).thenReturn(0);
        CountDownLatch blocked = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        doAnswer(invocation -> {
            started.countDown();
            blocked.await(30, TimeUnit.SECONDS);
            return null;
        }).when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'{', '}'}, responseInfo);
        assertTrue(started.await(5, TimeUnit.SECONDS));
        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'{', '}'}, responseInfo);

        assertEquals(1, publisher.getDroppedCount());
        verify(callbacks).printOutput(contains("byte budget"));
        verify(satelliteService, times(1)).sendHttpMessage(any());
        blocked.countDown();
    }

    @Test
    void queueDropLog_ignoresAWallClockRollback() throws Exception {
        publisher.extensionUnloaded();
        AtomicLong nanos = new AtomicLong(10_000_000_000L);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks,
                millis -> { }, nanos::get, () -> 0);
        when(requestInfo.getHeaders()).thenReturn(List.of(
                "GET /api/test HTTP/1.1",
                "Host: example.com",
                "Content-Type: application/json"));
        when(requestInfo.getMethod()).thenReturn("GET");
        when(requestInfo.getUrl()).thenReturn(new URL("http://example.com/api/test"));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/json"));
        when(responseInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        CountDownLatch blocked = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        doAnswer(invocation -> {
            started.countDown();
            blocked.await(30, TimeUnit.SECONDS);
            return null;
        }).when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        assertTrue(started.await(5, TimeUnit.SECONDS));
        for (int i = 0; i < 1025; i++) {
            publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        }
        verify(callbacks, times(1)).printOutput(contains("dropped oldest messages"));

        nanos.set(1L);
        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        verify(callbacks, times(1)).printOutput(contains("dropped oldest messages"));

        nanos.set(10_000_000_000L + HttpMessagePublisher.QUEUE_DROP_LOG_INTERVAL_NS);
        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        verify(callbacks, times(2)).printOutput(contains("dropped oldest messages"));
        blocked.countDown();
    }

    @Test
    void httpStatus_isNotRetriedBecauseSatelliteAlreadyAcceptedThePost() throws Exception {
        publisher.extensionUnloaded();
        AtomicLong slept = new AtomicLong(-1);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks,
                slept::set, System::nanoTime, () -> 0);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/json"));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        doThrow(new SatelliteMessageFailed("slow down", (short) 503, 2_500L))
                .when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        awaitExecutor();

        assertEquals(-1L, slept.get());
        verify(satelliteService, times(1)).sendHttpMessage(any());
        verify(callbacks).printError(contains("Status code(503)"));
    }

    @Test
    void ambiguousTransportFailure_isNotRetried() throws Exception {
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/json"));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        doThrow(new SatelliteMessageFailed("request timed out", (short) 0))
                .when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        awaitExecutor();

        verify(satelliteService, times(1)).sendHttpMessage(any());
    }

    @Test
    void postThatNeverLeftTheExtension_isRetriedOnce() throws Exception {
        publisher.extensionUnloaded();
        AtomicLong slept = new AtomicLong(-1);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks,
                slept::set, System::nanoTime, () -> 0);
        when(responseInfo.getHeaders()).thenReturn(List.of(
                "HTTP/1.1 200 OK",
                "Content-Type: application/json"));
        when(requestInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        when(responseInfo.getBodyOffset()).thenReturn(Integer.MAX_VALUE);
        doThrow(new SatelliteMessageFailed("Connection refused", (short) 0, null, true))
                .doReturn(null)
                .when(satelliteService).sendHttpMessage(any());

        publisher.sendHttpMessage(requestInfo, new byte[] {'x'}, "200", new byte[] {'y'}, responseInfo);
        awaitExecutor();

        assertEquals(HttpMessagePublisher.RETRY_BASE_DELAY_MS, slept.get());
        verify(satelliteService, times(2)).sendHttpMessage(any());
        verify(callbacks, never()).printError(anyString());
    }

    private void awaitExecutor() throws InterruptedException {
        var executor = publisher.getPublishExecutor();
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    private static byte[] headerBytes(String... lines) {
        return (String.join("\r\n", lines) + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] concat(byte[] head, byte[] tail) {
        byte[] out = new byte[head.length + tail.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(tail, 0, out, head.length, tail.length);
        return out;
    }
}
