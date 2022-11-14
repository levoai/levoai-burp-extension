package ai.levo;

import burp.*;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Implementation of HTTP activity listener.
 */
public class HttpMessageListener implements IHttpListener {
    private static final String COMMA_SEPARATED_EXTENSIONS =
            "css,ico,gif,jpg,jpeg,png,bmp,svg,avi,mpg,mpeg,mp3,m3u8,woff,woff2,ttf,eot,mp3,mp4,wav,mpg,mpeg,avi,mov,wmv,doc,xls,pdf,zip,tar,7z,rar,tgz,gz,exe,rtp,js";
    private static final Set<String> IGNORED_EXTENSIONS =
            Stream.of(COMMA_SEPARATED_EXTENSIONS.split(",")).map(s -> "." + s).collect(Collectors.toSet());

    /**
     * Ref on handler that will send HTTP messages to Levo's Satellite.
     */
    private final HttpMessagePublisher httpMessagePublisher;

    private final AlertWriter alertWriter;

    /**
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the
     * activity (tool name).
     */
    private final IBurpExtenderCallbacks callbacks;

    /**
     * Constructor.
     *
     * @param httpMessagePublisher Ref on handler that will send the HTTP messages to Levo's Satellite.
     * @param alertWriter          Ref on alert writer.
     * @param callbacks      Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the
     *                       source of the activity (tool name).
     */
    public HttpMessageListener(HttpMessagePublisher httpMessagePublisher, AlertWriter alertWriter,
                               IBurpExtenderCallbacks callbacks) {
        this.httpMessagePublisher = httpMessagePublisher;
        this.alertWriter = alertWriter;
        this.callbacks = callbacks;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        if (messageIsRequest) {
            return;
        }

        String toolName = callbacks.getToolName(toolFlag);
        // For now only process proxy's traffic.
        if (!"Proxy".equalsIgnoreCase(toolName)) {
            return;
        }

        try {
            // Send the HTTP message to Levo's Satellite according to the restriction options
            IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(message);
            if (this.shouldSendRequest(reqInfo)) {
                IResponseInfo responseInfoStatusCode = callbacks.getHelpers().analyzeResponse(message.getResponse());
                String statusCode = String.valueOf(responseInfoStatusCode.getStatusCode());
                byte[] response = message.getResponse();
                this.httpMessagePublisher.sendHttpMessage(reqInfo, message.getRequest(), statusCode, response);
            }
        } catch (Exception e) {
            this.alertWriter.writeAlert("Cannot send request: " + e.getMessage());
        }
    }

    /**
     * Determine if the current request must be sent according to the configuration options selected by the users.
     *
     * @param reqInfo Information about the current request
     * @return TRUE if the request must be sent, FALSE otherwise
     */
    private boolean shouldSendRequest(IRequestInfo reqInfo) {
        if (!ConfigMenu.IS_SENDING_ENABLED) {
            return false;
        }

        // Check if we must apply restriction about the URL scope
        if (ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE) {
            if (!this.callbacks.isInScope(reqInfo.getUrl())) {
                return false;
            }
        }

        // Check if we should discard the request based on the path.
        return shouldSendRequestsWithPath(reqInfo.getUrl().getPath());
    }

    private boolean shouldSendRequestsWithPath(String path) {
        // Handle more cases here.
        return IGNORED_EXTENSIONS.stream().noneMatch(path::endsWith);
    }
}
