package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class LevoSatelliteService {

    public static LevoSatelliteService create(String satelliteUrl, String organizationId, String environment, IBurpExtenderCallbacks callbacks) throws MalformedURLException {
        return new LevoSatelliteService(callbacks, satelliteUrl, organizationId, environment);
    }

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    private IHttpService service;
    private String hostHeader;

    private String organizationId;
    private String environment;

    public LevoSatelliteService(IBurpExtenderCallbacks callbacks, String satelliteUrl, String organizationId, String environment) throws MalformedURLException {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        var url = new URL(satelliteUrl);
        var port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
        this.hostHeader = buildHostHeader(url);
        this.service = helpers.buildHttpService(url.getHost(), port, url.getProtocol().equals("https"));
        this.organizationId = organizationId;
        this.environment = environment;
    }

    public void updateSatelliteUrl(String satelliteUrl) throws MalformedURLException {
        if (satelliteUrl == null || satelliteUrl.isEmpty()) {
            return;
        }
        var url = new URL(satelliteUrl);
        // Update the service if host is not empty
        if (url.getHost() != null && !url.getHost().isEmpty()) {
            var port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
            this.hostHeader = buildHostHeader(url);
            this.service = helpers.buildHttpService(url.getHost(), port, url.getProtocol().equals("https"));
        }
    }

    /**
     * Builds the Host header value per RFC 7230.
     * Omits the port number if it matches the default port (80 for HTTP, 443 for HTTPS).
     *
     * @param url The URL to extract host header from
     * @return Host header value (e.g., "example.com" or "example.com:8443")
     */
    private String buildHostHeader(URL url) {
        var port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
        if (port == url.getDefaultPort()) {
            return url.getHost();
        }
        return url.getHost() + ":" + port;
    }

    public void updateOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    public void updateEnvironment(String environment) {
        this.environment = environment;
    }

    public String getEnvironment() {
        return this.environment;
    }

    public IHttpRequestResponse sendHttpMessage(HttpMessage httpMessage) throws SatelliteMessageFailed, JsonProcessingException {
        if (organizationId == null || organizationId.isEmpty()) {
            throw new SatelliteMessageFailed("Organization ID is not set", (short)400);
        }
        var mapper = new ObjectMapper();
        var jsonBody = mapper.writeValueAsString(httpMessage);
        byte[] body = helpers.stringToBytes(jsonBody);
        List<String> newHeaders = new ArrayList<>();
        newHeaders.add("POST /1.0/ebpf/traces HTTP/1.1");
        // Set the host header explicitly since the host is being set as null sometimes.
        newHeaders.add("Host: " + hostHeader);
        newHeaders.add("x-levo-organization-id: " + organizationId);
        var message = helpers.buildHttpMessage(newHeaders, body);
        var requestResponse = this.callbacks.makeHttpRequest(service, message, false);

        var response = requestResponse.getResponse();
        if (response == null) {
            throw new SatelliteMessageFailed("Failed to connect to Levo Satellite. Connection refused or network error.", (short)0);
        }
        var responseInfo = helpers.analyzeResponse(response);

        if (responseInfo.getStatusCode() >= 400) {
            int len = response.length - responseInfo.getBodyOffset();
            var result = new byte[len];
            System.arraycopy(response, responseInfo.getBodyOffset(), result, 0, len);
            throw new SatelliteMessageFailed(new String(result), responseInfo.getStatusCode());
        }

        return requestResponse;
    }
}
