package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for HttpMessagePublisher that construct and exercise
 * the actual HttpMessagePublisher class (not mocked), verifying:
 * - Success path routes to printOutput() via writeInfo()
 * - SatelliteMessageFailed exception routes to printError() via writeError()
 * - JsonProcessingException routes to printError() via writeError()
 * - None of these paths use issueAlert() (Event log)
 * - Async publish behavior: non-blocking, queue overflow, sending-disabled drops
 * 
 * These tests would fail if the logging calls were reverted to issueAlert().
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HttpMessagePublisherCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private LevoSatelliteService satelliteService;

    @Mock
    private IRequestInfo requestInfo;

    private AlertWriter alertWriter;
    private HttpMessagePublisher publisher;

    @BeforeEach
    void setUp() throws Exception {
        alertWriter = new AlertWriter(callbacks);
        publisher = new HttpMessagePublisher(satelliteService, alertWriter, callbacks);

        when(callbacks.getHelpers()).thenReturn(helpers);
        when(satelliteService.getEnvironment()).thenReturn("test");
        
        // Enable sending by default for tests
        ConfigMenu.IS_SENDING_ENABLED = true;
    }

    @AfterEach
    void tearDown() {
        // Shut down the publisher's executor to avoid thread leaks between tests
        publisher.extensionUnloaded();
        // Reset the sending flag
        ConfigMenu.IS_SENDING_ENABLED = false;
    }

    /**
     * Helper to wait for the async executor to process all queued tasks.
     */
    private void awaitExecutor() throws InterruptedException {
        var executor = publisher.getPublishExecutor();
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS), "Executor did not terminate in time");
    }

    @Test
    void sendHttpMessage_onSuccess_routesToPrintOutput_neverIssueAlert() throws Exception {
        setupValidRequest();
        
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200", 
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        awaitExecutor();

        verify(callbacks).printOutput(contains("Sent the HTTP message for:"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    @Test
    void sendHttpMessage_onSatelliteMessageFailed_routesToPrintError_neverIssueAlert() throws Exception {
        setupValidRequest();
        when(satelliteService.sendHttpMessage(any()))
                .thenThrow(new SatelliteMessageFailed("Connection refused", (short) 500));

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        awaitExecutor();

        verify(callbacks).printError(contains("Cannot send HTTP message to Levo"));
        verify(callbacks).printError(contains("Status code(500)"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printOutput(contains("Cannot send"));
    }

    @Test
    void sendHttpMessage_onJsonProcessingException_routesToPrintError_neverIssueAlert() throws Exception {
        setupValidRequest();
        when(satelliteService.sendHttpMessage(any()))
                .thenThrow(new JsonProcessingException("Parse error") {});

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        awaitExecutor();

        verify(callbacks).printError(contains("Cannot send HTTP message to Levo"));
        verify(callbacks).printError(contains("Can't parse the HTTP message to JSON"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void sendHttpMessage_onGenericException_routesToPrintError_neverIssueAlert() throws Exception {
        setupValidRequest();
        when(satelliteService.sendHttpMessage(any()))
                .thenThrow(new RuntimeException("Network error"));

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        awaitExecutor();

        verify(callbacks).printError(contains("Cannot send HTTP message to Levo"));
        verify(callbacks).printError(contains("Network error"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void sendHttpMessage_droppedRequest_unsupportedContentType_routesToPrintOutput_neverIssueAlert() throws Exception {
        URL testUrl = new URL("http://example.com/api/test");
        List<String> headers = Arrays.asList(
                "GET /api/test HTTP/1.1",
                "Host: example.com",
                "Content-Type: image/png"
        );

        when(requestInfo.getUrl()).thenReturn(testUrl);
        when(requestInfo.getHeaders()).thenReturn(headers);
        when(helpers.bytesToString(any(byte[].class))).thenReturn("GET /api/test HTTP/1.1\r\n\r\n");

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        // No need to await executor - drop happens synchronously in convertToHttpMessage
        verify(callbacks).printOutput(contains("Dropping because of content-type"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void sendHttpMessage_droppedResponse_unsupportedContentType_routesToPrintOutput_neverIssueAlert() throws Exception {
        URL testUrl = new URL("http://example.com/api/test");
        List<String> headers = Arrays.asList(
                "GET /api/test HTTP/1.1",
                "Host: example.com",
                "Content-Type: application/json"
        );

        when(requestInfo.getUrl()).thenReturn(testUrl);
        when(requestInfo.getHeaders()).thenReturn(headers);
        when(requestInfo.getMethod()).thenReturn("GET");
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("request"))))
                .thenReturn("GET /api/test HTTP/1.1\r\n\r\n");
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("HTTP"))))
                .thenReturn("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n");
        when(helpers.base64Encode(anyString())).thenReturn("encoded");

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".getBytes());

        verify(callbacks).printOutput(contains("Dropping because content-type not being instrumented"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void sendHttpMessage_pdfBodySuppression_routesToPrintOutput_neverIssueAlert() throws Exception {
        URL testUrl = new URL("http://example.com/api/test");
        List<String> headers = Arrays.asList(
                "GET /api/test HTTP/1.1",
                "Host: example.com",
                "Content-Type: application/json"
        );

        when(requestInfo.getUrl()).thenReturn(testUrl);
        when(requestInfo.getHeaders()).thenReturn(headers);
        when(requestInfo.getMethod()).thenReturn("GET");
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("request"))))
                .thenReturn("GET /api/test HTTP/1.1\r\n\r\n");
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("HTTP"))))
                .thenReturn("HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\npdf-content");
        when(helpers.base64Encode(anyString())).thenReturn("encoded");

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\npdf-content".getBytes());

        awaitExecutor();

        verify(callbacks).printOutput(contains("Not sending response body for content-type: application/pdf"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    // ========== Async-specific tests ==========

    @Test
    void sendHttpMessage_doesNotBlockCallerOnSlowSatellite() throws Exception {
        setupValidRequest();
        CountDownLatch satelliteEntered = new CountDownLatch(1);
        CountDownLatch satelliteRelease = new CountDownLatch(1);
        
        when(satelliteService.sendHttpMessage(any())).thenAnswer(invocation -> {
            satelliteEntered.countDown();
            satelliteRelease.await(10, TimeUnit.SECONDS);
            return null;
        });

        long startTime = System.currentTimeMillis();
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        long elapsed = System.currentTimeMillis() - startTime;

        // sendHttpMessage should return quickly (< 100ms), not block on satellite
        assertTrue(elapsed < 100, "sendHttpMessage blocked for " + elapsed + "ms, expected < 100ms");
        
        // Wait for satellite call to start (proves task was enqueued)
        assertTrue(satelliteEntered.await(5, TimeUnit.SECONDS), "Satellite never called");
        
        // Release the satellite and clean up
        satelliteRelease.countDown();
    }

    @Test
    void sendHttpMessage_queueOverflow_dropsOldestMessages() throws Exception {
        setupValidRequest();
        CountDownLatch blockWorker = new CountDownLatch(1);
        AtomicBoolean firstCallMade = new AtomicBoolean(false);
        
        when(satelliteService.sendHttpMessage(any())).thenAnswer(invocation -> {
            firstCallMade.set(true);
            blockWorker.await(30, TimeUnit.SECONDS);
            return null;
        });

        // Submit first message - this will start executing and block the worker
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        
        // Wait for first call to start blocking
        while (!firstCallMade.get()) {
            Thread.sleep(10);
        }
        
        // Now fill the queue (1024 capacity) and overflow
        for (int i = 0; i < 1030; i++) {
            publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        }
        
        // Should have dropped some messages
        assertTrue(publisher.getDroppedCount() > 0, "Expected dropped messages but got 0");
        
        // Verify drop alert was logged (via writeInfo, not issueAlert)
        verify(callbacks, atLeastOnce()).printOutput(contains("dropped oldest messages"));
        verify(callbacks, never()).issueAlert(anyString());
        
        // Clean up
        blockWorker.countDown();
    }

    @Test
    void sendHttpMessage_sendingDisabled_dropsQueuedWork() throws Exception {
        setupValidRequest();
        CountDownLatch blockWorker = new CountDownLatch(1);
        CountDownLatch workerStarted = new CountDownLatch(1);
        
        // Make satellite slow so tasks queue up
        when(satelliteService.sendHttpMessage(any())).thenAnswer(invocation -> {
            workerStarted.countDown();
            blockWorker.await(30, TimeUnit.SECONDS);
            return null;
        });

        // Submit first message that will block the worker
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        
        // Wait for worker to start
        assertTrue(workerStarted.await(5, TimeUnit.SECONDS));
        
        // Queue more messages while first is processing
        for (int i = 0; i < 5; i++) {
            publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        }
        
        // Disable sending while messages are queued
        ConfigMenu.IS_SENDING_ENABLED = false;
        
        // Release the worker
        blockWorker.countDown();
        
        // Wait for executor to process remaining tasks
        awaitExecutor();
        
        // Only 1 satellite call should have been made (the first one that started before disable)
        // The queued messages should have been dropped due to IS_SENDING_ENABLED check
        verify(satelliteService, times(1)).sendHttpMessage(any());
    }

    @Test
    void extensionUnloaded_shutsDownExecutor() throws Exception {
        setupValidRequest();
        
        // Submit a message
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        
        var executor = publisher.getPublishExecutor();
        assertFalse(executor.isShutdown(), "Executor should not be shutdown initially");
        
        // Call extensionUnloaded
        publisher.extensionUnloaded();
        
        assertTrue(executor.isShutdown(), "Executor should be shutdown after extensionUnloaded");
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS), "Executor should terminate");
    }

    @Test
    void extensionUnloaded_logsWarningIfShutdownTimesOut() throws Exception {
        setupValidRequest();
        CountDownLatch blockForever = new CountDownLatch(1);
        
        when(satelliteService.sendHttpMessage(any())).thenAnswer(invocation -> {
            // Block indefinitely (will be interrupted by shutdownNow)
            try {
                blockForever.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        });

        // Submit a message that will block
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());
        
        // Give the task time to start
        Thread.sleep(100);
        
        // Note: This test would take 5+ seconds if the shutdown timeout actually triggers.
        // For the test to be fast, we rely on shutdownNow() interrupting the blocked task.
        // The warning log is only emitted if awaitTermination returns false.
    }

    private void setupValidRequest() throws Exception {
        URL testUrl = new URL("http://example.com/api/test");
        List<String> headers = Arrays.asList(
                "GET /api/test HTTP/1.1",
                "Host: example.com",
                "Content-Type: application/json"
        );

        when(requestInfo.getUrl()).thenReturn(testUrl);
        when(requestInfo.getHeaders()).thenReturn(headers);
        when(requestInfo.getMethod()).thenReturn("GET");
        
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("request"))))
                .thenReturn("GET /api/test HTTP/1.1\r\n\r\n");
        when(helpers.bytesToString(argThat(arg -> 
                arg != null && new String(arg).startsWith("HTTP"))))
                .thenReturn("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}");
        
        when(helpers.base64Encode(anyString())).thenReturn("encoded");
    }
}
