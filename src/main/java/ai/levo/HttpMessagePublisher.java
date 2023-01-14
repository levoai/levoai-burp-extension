package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.*;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * Handles the HTTP messages that are received and sends them to Levo's Satellite.
 */
public class HttpMessagePublisher implements IExtensionStateListener {

    private static final String TWO_LINES_PATTERN = "\r\n\r\n";
    private static final String NEW_LINE_PATTERN = "\r\n";
    private static final String DEFAULT_SERVICE_NAME = "default";
    private static final String CONTENT_TYPE_HEADER = "content-type";

    private static final List<String> ACCEPTED_CONTENT_TYPES = Arrays.asList(
            "application/json",
            "application/x-www-form-urlencoded"
    );
    private static final String SERVICE_NAME_RESOURCE_KEY = "service_name";

    private final IBurpExtenderCallbacks callbacks;

    /**
     * Ref on alert writer.
     */
    private final AlertWriter alertWriter;

    private final LevoSatelliteService satelliteService;

    /**
     * Constructor.
     *
     * @param satelliteService Levo's Satellite Service
     * @param alertWriter Ref on alert writer.
     * @param callbacks callbacks
     */
    public HttpMessagePublisher(LevoSatelliteService satelliteService, AlertWriter alertWriter, IBurpExtenderCallbacks callbacks) {
        this.alertWriter = alertWriter;
        this.callbacks = callbacks;
        this.satelliteService = satelliteService;
    }

    /**
     * Send an HTTP message to Levo's Satellite.
     *
     * @param reqInfo    Details of the request to be processed.
     * @param reqContent Raw content of the request.
     */
    void sendHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) {
        HttpMessage httpMessage = convertToHttpMessage(reqInfo, reqContent, statusCode, resContent);
        if (httpMessage == null) {
            return;
        }

        try {
            satelliteService.sendHttpMessage(httpMessage);
            this.alertWriter.writeAlert("Sent the HTTP message for: "
                    + reqInfo.getUrl().getHost() + reqInfo.getUrl().getPath() + " to Levo's Satellite.");
        } catch (SatelliteMessageFailed e) {
            this.alertWriter.writeAlert("Cannot send HTTP message to Levo. Status code("+ e.getStatusCode() +"): " + e.getMessage());
        } catch (JsonProcessingException e) {
            this.alertWriter.writeAlert("Cannot send HTTP message to Levo: Can't parse the HTTP message to JSON.");
        }
    }

    private boolean shouldDropMessage(String contentType) {
        if (contentType == null) {
            return false;
        }

        for (String acceptedContentType : ACCEPTED_CONTENT_TYPES) {
            if (contentType.startsWith(acceptedContentType)) {
                return false;
            }
        }

        //this.alertWriter.writeAlert("Not sending content-type: " + contentType + " to Levo.");
        return true;
    }

    private HttpMessage convertToHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) {
        HttpMessage.Request request = new HttpMessage.Request();
        request.setHeaders(convertHeadersToMap(reqInfo.getHeaders()));

        // Ignore if the request body isn't acceptable content type
        if (shouldDropMessage(request.getHeaders().get(CONTENT_TYPE_HEADER))) {
            return null;
        }

        // Add the method and path separately in the headers.
        request.getHeaders().put(":method", reqInfo.getMethod());
        request.getHeaders().put(":path", reqInfo.getUrl().getPath());

        String requestBody = callbacks.getHelpers().bytesToString(reqContent);
        String[] parts = requestBody.split(TWO_LINES_PATTERN);
        if (parts.length > 1 && parts[1].length() > 0) {
            // Base64 encode the body.
            request.setBody(callbacks.getHelpers().base64Encode(parts[1]));
        } else {
            request.setBody("");
        }

        HttpMessage.Response response = new HttpMessage.Response();
        String responseBody = callbacks.getHelpers().bytesToString(resContent);
        parts = responseBody.split(TWO_LINES_PATTERN);
        if (parts.length > 1 && parts[1].length() > 0) {
            // Base64 encode the response body.
            response.setBody(callbacks.getHelpers().base64Encode(parts[1]));
        } else {
            // Don't drop the message if the response body is empty.
            response.setBody("");
        }

        // Create response headers from the first part of the response. Ignore the status line.
        String[] responseHeaders = parts[0].split(NEW_LINE_PATTERN);
        if (responseHeaders.length > 1) {
            // Create a list from an array and remove the first element since that's status line.
            List<String> headers = java.util.Arrays.asList(responseHeaders);
            headers = headers.subList(1, headers.size());
            response.setHeaders(convertHeadersToMap(headers));
        }

        // Ignore if the response isn't acceptable content type
        if (shouldDropMessage(response.getHeaders().get(CONTENT_TYPE_HEADER))) {
            return null;
        }

        // Add the status code separately in the headers.
        response.getHeaders().put(":status", statusCode);

        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setRequest(request);
        httpMessage.setResponse(response);
        httpMessage.setResource(Map.of(SERVICE_NAME_RESOURCE_KEY, DEFAULT_SERVICE_NAME));
        httpMessage.setSpanKind("SERVER");
        httpMessage.setTraceId(UUID.randomUUID().toString());
        httpMessage.setSpanId(UUID.randomUUID().toString());
        return httpMessage;
    }

    private Map<String, String> convertHeadersToMap(List<String> headers) {
        // Convert the list of headers into a map by splitting based on the first colon
        Map<String, String> headersMap = new java.util.HashMap<>();
        for (String header : headers) {
            String[] headerParts = header.split(":", 2);
            if (headerParts.length == 2) {
                headersMap.put(headerParts[0].trim().toLowerCase(), headerParts[1].trim());
            }
        }

        return headersMap;
    }

    @Override
    public void extensionUnloaded() {
        // TODO: Implement this method in future versions.
    }
}
