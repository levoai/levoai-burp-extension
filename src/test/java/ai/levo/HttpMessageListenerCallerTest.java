package ai.levo;

import burp.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URL;

import static org.mockito.Mockito.*;

/**
 * Integration test that exercises a real production caller path (HttpMessageListener)
 * end-to-end against a mocked IBurpExtenderCallbacks. Verifies that errors go to
 * printError (not printOutput / issueAlert) when exceptions occur during message processing.
 * 
 * This test would fail if someone reverted the caller to use the wrong logging method.
 */
@ExtendWith(MockitoExtension.class)
class HttpMessageListenerCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private HttpMessagePublisher httpMessagePublisher;

    @Mock
    private IHttpRequestResponse httpRequestResponse;

    @Mock
    private IRequestInfo requestInfo;

    @Mock
    private IResponseInfo responseInfo;

    private AlertWriter alertWriter;
    private HttpMessageListener httpMessageListener;

    @BeforeEach
    void setUp() {
        alertWriter = new AlertWriter(callbacks);
        httpMessageListener = new HttpMessageListener(httpMessagePublisher, alertWriter, callbacks);
    }

    @Test
    void processHttpMessage_whenExceptionOccurs_shouldRouteErrorToPrintError_notPrintOutputOrIssueAlert() throws Exception {
        when(callbacks.getToolName(anyInt())).thenReturn("proxy");
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(requestInfo);
        when(requestInfo.getUrl()).thenReturn(new URL("http://example.com/api/test"));
        
        ConfigMenu.IS_SENDING_ENABLED = true;
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;
        
        when(helpers.analyzeResponse(any())).thenThrow(new RuntimeException("Simulated processing error"));

        httpMessageListener.processHttpMessage(4, false, httpRequestResponse);

        verify(callbacks).printError(contains("Cannot send request:"));
        verify(callbacks).printError(contains("Simulated processing error"));
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void processHttpMessage_whenPublisherThrows_shouldRouteErrorToPrintError_notIssueAlert() throws Exception {
        when(callbacks.getToolName(anyInt())).thenReturn("proxy");
        when(callbacks.getHelpers()).thenReturn(helpers);
        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(requestInfo);
        when(requestInfo.getUrl()).thenReturn(new URL("http://example.com/api/data"));
        when(helpers.analyzeResponse(any())).thenReturn(responseInfo);
        when(responseInfo.getStatusCode()).thenReturn((short) 200);
        when(httpRequestResponse.getResponse()).thenReturn(new byte[0]);
        when(httpRequestResponse.getRequest()).thenReturn(new byte[0]);
        
        ConfigMenu.IS_SENDING_ENABLED = true;
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;
        
        doThrow(new RuntimeException("Network failure")).when(httpMessagePublisher)
                .sendHttpMessage(any(), any(), anyString(), any());

        httpMessageListener.processHttpMessage(4, false, httpRequestResponse);

        verify(callbacks).printError(contains("Cannot send request:"));
        verify(callbacks).printError(contains("Network failure"));
        verify(callbacks, never()).printOutput(contains("Cannot send"));
        verify(callbacks, never()).issueAlert(anyString());
    }
}
