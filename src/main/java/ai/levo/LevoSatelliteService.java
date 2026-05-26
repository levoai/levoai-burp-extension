package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    /**
     * Immutable pair of the destination {@link IHttpService} and the matching Host header.
     * Bundling them together lets the EDT swap both values atomically via a single
     * {@code volatile} write so a reader (the publish worker) can never observe a
     * mismatched pair — e.g., the new service with the old Host header — when the
     * Satellite URL is changed at runtime. That matters if anything between Burp and
     * the Satellite routes by Host header (virtual hosting / fronting proxy).
     */
    private static final class Endpoint {
        final IHttpService service;
        final String hostHeader;

        Endpoint(IHttpService service, String hostHeader) {
            this.service = service;
            this.hostHeader = hostHeader;
        }
    }

    // Mutable config updated from the Swing EDT (ConfigMenu actions) and read from the
    // publish worker thread. volatile gives the worker visibility of EDT writes without
    // synchronization. endpoint is a single atomic snapshot of {service, hostHeader}.
    private volatile Endpoint endpoint;
    private volatile String organizationId;
    private volatile String environment;

    public LevoSatelliteService(IBurpExtenderCallbacks callbacks, String satelliteUrl, String organizationId, String environment) throws MalformedURLException {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.endpoint = buildEndpoint(new URL(satelliteUrl));
        this.organizationId = organizationId;
        this.environment = environment;
    }

    public void updateSatelliteUrl(String satelliteUrl) throws MalformedURLException {
        if (satelliteUrl == null || satelliteUrl.isEmpty()) {
            return;
        }
        var url = new URL(satelliteUrl);
        if (url.getHost() != null && !url.getHost().isEmpty()) {
            // Atomic swap — service and hostHeader become visible together.
            this.endpoint = buildEndpoint(url);
        }
    }

    private Endpoint buildEndpoint(URL url) {
        var port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();
        var svc = helpers.buildHttpService(url.getHost(), port, url.getProtocol().equals("https"));
        return new Endpoint(svc, buildHostHeader(url));
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
        // Read the endpoint snapshot once so service and hostHeader stay consistent
        // even if the EDT swaps the endpoint mid-send.
        Endpoint ep = this.endpoint;
        var mapper = new ObjectMapper();
        var jsonBody = mapper.writeValueAsString(httpMessage);
        byte[] body = helpers.stringToBytes(jsonBody);
        List<String> newHeaders = new ArrayList<>();
        newHeaders.add("POST /1.0/ebpf/traces HTTP/1.1");
        // Set the host header explicitly since the host is being set as null sometimes.
        newHeaders.add("Host: " + ep.hostHeader);
        newHeaders.add("Content-Type: application/json");
        newHeaders.add("x-levo-organization-id: " + organizationId);
        var message = helpers.buildHttpMessage(newHeaders, body);
        var requestResponse = this.callbacks.makeHttpRequest(ep.service, message, false);

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
