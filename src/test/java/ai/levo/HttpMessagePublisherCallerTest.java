package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
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

import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for HttpMessagePublisher that construct and exercise
 * the actual HttpMessagePublisher class (not mocked), verifying:
 * - Success path routes to printOutput() via writeInfo()
 * - SatelliteMessageFailed exception routes to printError() via writeError()
 * - JsonProcessingException routes to printError() via writeError()
 * - None of these paths use issueAlert() (Event log)
 * 
 * These tests would fail if the logging calls at lines 96, 99, 101 were
 * reverted to issueAlert().
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
    }

    @Test
    void sendHttpMessage_onSuccess_routesToPrintOutput_neverIssueAlert() throws Exception {
        setupValidRequest();
        
        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200", 
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

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

        verify(callbacks).printError(contains("Cannot send HTTP message to Levo"));
        verify(callbacks).printError(contains("Can't parse the HTTP message to JSON"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void sendHttpMessage_allPaths_neverUseIssueAlert() throws Exception {
        setupValidRequest();

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        reset(callbacks);
        when(callbacks.getHelpers()).thenReturn(helpers);
        setupValidRequest();
        when(satelliteService.sendHttpMessage(any()))
                .thenThrow(new SatelliteMessageFailed("Error", (short) 400));

        publisher.sendHttpMessage(requestInfo, "request".getBytes(), "200",
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".getBytes());

        verify(callbacks, never()).issueAlert(anyString());
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
