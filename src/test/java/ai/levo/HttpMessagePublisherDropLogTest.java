package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HttpMessagePublisherDropLogTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private IRequestInfo reqInfo;

    @Mock
    private LevoSatelliteService satelliteService;

    private AtomicLong now;
    private HttpMessagePublisher publisher;

    @BeforeEach
    void setUp() {
        now = new AtomicLong(1_000L);
        AlertWriter alertWriter = new AlertWriter(callbacks, now::get);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks);
        ConfigMenu.IS_SENDING_ENABLED = true;
    }

    @AfterEach
    void tearDown() {
        publisher.extensionUnloaded();
        ConfigMenu.IS_SENDING_ENABLED = false;
    }

    @Test
    void droppedResponse_logsContentType_andRateLimitsRepeats() throws Exception {
        stubJsonGetRequest();

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/html"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/html"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/html"));

        verify(callbacks, times(1)).printOutput(
                "Dropping because response content-type 'text/html' is not instrumented");
        verify(satelliteService, never()).sendHttpMessage(any());
    }

    @Test
    void droppedResponse_includesCharsetInMessage_butRateLimitsByMediaType() throws Exception {
        stubJsonGetRequest();

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200",
                responseBytes("text/html; charset=UTF-8"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200",
                responseBytes("text/html; charset=utf-8"));

        verify(callbacks, times(1)).printOutput(
                "Dropping because response content-type 'text/html; charset=UTF-8' is not instrumented");
        verify(callbacks, never()).printOutput(contains("charset=utf-8"));
        verify(satelliteService, never()).sendHttpMessage(any());
    }

    @Test
    void droppedResponse_logsSuppressedCountAfterWindow() throws Exception {
        stubJsonGetRequest();

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/css"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/css"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/css"));
        now.addAndGet(AlertWriter.RATE_LIMIT_WINDOW_MS);
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("text/css"));

        verify(callbacks).printOutput(
                "Dropping because response content-type 'text/css' is not instrumented");
        verify(callbacks).printOutput(
                "Dropping because response content-type 'text/css' is not instrumented (2 similar messages suppressed)");
    }

    @Test
    void droppedRequest_logsContentType_notMissingHeaderMessage() throws Exception {
        when(reqInfo.getHeaders()).thenReturn(List.of(
                "POST /upload HTTP/1.1",
                "Content-Type: multipart/form-data; boundary=abc"
        ));

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));

        verify(callbacks, times(1)).printOutput(
                "Dropping because request content-type 'multipart/form-data; boundary=abc' is not instrumented");
        verify(callbacks, never()).printOutput(contains("header not present"));
        verifyNoInteractions(satelliteService);
    }

    @Test
    void satellite401_isRateLimitedToErrorsTab() throws Exception {
        stubAcceptedJsonRoundTrip();
        String errorBody = "{\"error\":{\"code\":401,\"message\":\"Authentication required\",\"subcode\":\"unauthorized\"}}";
        when(satelliteService.sendHttpMessage(any())).thenThrow(
                new SatelliteMessageFailed(errorBody, (short) 401));

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        awaitExecutor();

        verify(callbacks, times(1)).printError(
                "Cannot send HTTP message to Levo. Status code(401): " + errorBody);
        verify(callbacks, never()).printOutput(contains("Cannot send"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void satellite401_logsSuppressedCountAfterWindow() throws Exception {
        publisher.extensionUnloaded();
        AlertWriter spyWriter = spy(new AlertWriter(callbacks, now::get));
        CountDownLatch firstBurstLogged = new CountDownLatch(3);
        doAnswer(invocation -> {
            invocation.callRealMethod();
            firstBurstLogged.countDown();
            return null;
        }).when(spyWriter).writeErrorRateLimited(anyString(), anyString());
        publisher = new HttpMessagePublisher(satelliteService, spyWriter, callbacks);

        stubAcceptedJsonRoundTrip();
        String errorBody = "{\"error\":{\"code\":401,\"message\":\"Authentication required\",\"subcode\":\"unauthorized\"}}";
        when(satelliteService.sendHttpMessage(any())).thenThrow(
                new SatelliteMessageFailed(errorBody, (short) 401));

        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        assertTrue(firstBurstLogged.await(5, TimeUnit.SECONDS), "First 401 burst did not finish logging");
        now.addAndGet(AlertWriter.RATE_LIMIT_WINDOW_MS);
        publisher.sendHttpMessage(reqInfo, requestBytes(), "200", responseBytes("application/json"));
        awaitExecutor();

        String message = "Cannot send HTTP message to Levo. Status code(401): " + errorBody;
        verify(callbacks).printError(message);
        verify(callbacks).printError(message + " (2 similar messages suppressed)");
    }

    private void awaitExecutor() throws InterruptedException {
        var executor = publisher.getPublishExecutor();
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "Executor did not terminate in time");
    }

    private void stubAcceptedJsonRoundTrip() throws Exception {
        stubJsonGetRequest();
        when(helpers.base64Encode(anyString())).thenReturn("encoded");
    }

    private void stubJsonGetRequest() throws Exception {
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(reqInfo.getHeaders()).thenReturn(List.of(
                "GET /page HTTP/1.1",
                "Host: example.com"
        ));
        when(reqInfo.getMethod()).thenReturn("GET");
        when(reqInfo.getUrl()).thenReturn(new URL("http://example.com/page"));
        when(helpers.bytesToString(any(byte[].class))).thenAnswer(invocation ->
                new String((byte[]) invocation.getArgument(0), StandardCharsets.UTF_8));
    }

    private static byte[] requestBytes() {
        return "GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] responseBytes(String contentType) {
        String response = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\nbody";
        return response.getBytes(StandardCharsets.UTF_8);
    }
}
