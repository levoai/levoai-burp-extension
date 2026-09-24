package ai.levo;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.JMenuItem;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SendToLevoMenuTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private IExtensionHelpers helpers;

    @Mock
    private HttpMessagePublisher publisher;

    @Mock
    private IContextMenuInvocation invocation;

    @Mock
    private IHttpRequestResponse message;

    @Mock
    private IRequestInfo requestInfo;

    @Mock
    private IResponseInfo responseInfo;

    private SendToLevoMenu menu;
    private int stubSequence;

    @BeforeEach
    void setUp() {
        menu = new SendToLevoMenu(callbacks, publisher);
        ConfigMenu.IS_SENDING_ENABLED = true;
    }

    @AfterEach
    void tearDown() {
        ConfigMenu.IS_SENDING_ENABLED = false;
    }

    @Test
    void createMenuItems_withoutMessages_returnsNull() {
        when(invocation.getSelectedMessages()).thenReturn(null);
        assertNull(menu.createMenuItems(invocation));

        when(invocation.getSelectedMessages()).thenReturn(new IHttpRequestResponse[0]);
        assertNull(menu.createMenuItems(invocation));
    }

    @Test
    void createMenuItems_withAMessage_returnsSendItem() {
        when(invocation.getSelectedMessages()).thenReturn(new IHttpRequestResponse[]{message});

        List<JMenuItem> items = menu.createMenuItems(invocation);

        assertEquals(1, items.size());
        assertEquals(SendToLevoMenu.MENU_LABEL, items.get(0).getText());
    }

    @Test
    void supportedContentType_isSentWithNoNotification() throws Exception {
        stubMessage("GET", "https://example.com/api",
                List.of("GET /api HTTP/1.1", "Host: example.com"),
                List.of("HTTP/1.1 200 OK", "Content-Type: application/json"));
        List<String> notices = new ArrayList<>();

        menu.sendSelected(new IHttpRequestResponse[]{message}, notices::add);

        verify(publisher).sendHttpMessage(eq(requestInfo), any(), eq("200"), any());
        assertTrue(notices.isEmpty());
    }

    @Test
    void unsupportedContentType_isNotSentAndNamesTheType() throws Exception {
        stubMessage("GET", "https://www.google.com/async/hpba?vet=1",
                List.of("GET /async/hpba HTTP/1.1"),
                List.of("HTTP/1.1 200 OK", "Content-Type: text/html; charset=UTF-8"));
        List<String> notices = new ArrayList<>();

        menu.sendSelected(new IHttpRequestResponse[]{message}, notices::add);

        verify(publisher, never()).sendHttpMessage(any(), any(), any(), any());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).startsWith("Not sending this message because its content type is not supported."));
        assertTrue(notices.get(0).contains("response content-type 'text/html; charset=UTF-8' is not supported"));
        assertTrue(notices.get(0).contains("GET https://www.google.com/async/hpba?vet=1"));
    }

    @Test
    void mixedSelection_sendsMatchesAndReportsTheRest() throws Exception {
        IHttpRequestResponse html = mock(IHttpRequestResponse.class);
        IRequestInfo htmlRequest = mock(IRequestInfo.class);
        IResponseInfo htmlResponse = mock(IResponseInfo.class);
        stubOne(html, htmlRequest, htmlResponse, "GET", "https://example.com/",
                List.of("GET / HTTP/1.1"),
                List.of("HTTP/1.1 200 OK", "Content-Type: text/html"));

        stubMessage("POST", "https://example.com/api",
                List.of("POST /api HTTP/1.1", "Content-Type: application/json"),
                List.of("HTTP/1.1 200 OK", "Content-Type: Application/JSON"));

        when(callbacks.getHelpers()).thenReturn(helpers);
        List<String> notices = new ArrayList<>();

        menu.sendSelected(new IHttpRequestResponse[]{html, message}, notices::add);

        verify(publisher, times(1)).sendHttpMessage(eq(requestInfo), any(), eq("200"), any());
        verify(publisher, never()).sendHttpMessage(eq(htmlRequest), any(), any(), any());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).contains("response content-type 'text/html' is not supported"));
        assertTrue(notices.get(0).contains("Sent 1 other message."));
    }

    @Test
    void sendingDisabled_notifiesAndDoesNotSend() {
        ConfigMenu.IS_SENDING_ENABLED = false;
        List<String> notices = new ArrayList<>();

        menu.sendSelected(new IHttpRequestResponse[]{message}, notices::add);

        verifyNoInteractions(publisher);
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).contains("Sending to Levo is turned off."));
    }

    @Test
    void contentTypeRejection_allowsMissingRequestTypeAndMixedCaseJson() {
        assertNull(SendToLevoMenu.contentTypeRejection(
                "GET", "https://example.com/api", null, "Application/JSON; charset=UTF-8"));
        assertNotNull(SendToLevoMenu.contentTypeRejection(
                "POST", "https://example.com/upload", "multipart/form-data; boundary=abc", "application/json"));
    }

    private void stubMessage(String method, String url, List<String> requestHeaders, List<String> responseHeaders)
            throws Exception {
        stubOne(message, requestInfo, responseInfo, method, url, requestHeaders, responseHeaders);
        when(callbacks.getHelpers()).thenReturn(helpers);
    }

    private void stubOne(IHttpRequestResponse httpMessage, IRequestInfo req, IResponseInfo res,
                         String method, String url, List<String> requestHeaders, List<String> responseHeaders)
            throws Exception {
        byte[] requestBytes = new byte[]{(byte) ++stubSequence};
        byte[] responseBytes = new byte[]{(byte) ++stubSequence};
        when(httpMessage.getRequest()).thenReturn(requestBytes);
        when(httpMessage.getResponse()).thenReturn(responseBytes);
        when(helpers.analyzeRequest(httpMessage)).thenReturn(req);
        when(helpers.analyzeResponse(responseBytes)).thenReturn(res);
        when(req.getHeaders()).thenReturn(requestHeaders);
        when(req.getMethod()).thenReturn(method);
        when(req.getUrl()).thenReturn(new URL(url));
        when(res.getHeaders()).thenReturn(responseHeaders);
        lenient().when(res.getStatusCode()).thenReturn((short) 200);
    }
}
