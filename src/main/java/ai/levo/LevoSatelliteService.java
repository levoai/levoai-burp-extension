package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class LevoSatelliteService {

    private static final String TRACES_PATH = "/1.0/ebpf/traces";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    /**
     * Direct connection. Burp's HTTP stack would apply match-and-replace, session
     * rules, and the upstream proxy, and could capture the Satellite post again.
     */
    private static final ProxySelector DIRECT = new ProxySelector() {
        @Override
        public List<Proxy> select(URI uri) {
            return Collections.singletonList(Proxy.NO_PROXY);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        }
    };

    public static LevoSatelliteService create(String satelliteUrl, String organizationId, String environment) throws MalformedURLException {
        return new LevoSatelliteService(satelliteUrl, organizationId, environment);
    }

    // Mutable config updated from the Swing EDT (ConfigMenu actions) and read from the
    // publish worker thread. volatile gives the worker visibility of EDT writes without
    // synchronization. satelliteUrl is swapped as a single reference.
    private volatile URL satelliteUrl;
    private volatile String organizationId;
    private volatile String environment;
    private final HttpClient httpClient;

    public LevoSatelliteService(String satelliteUrl, String organizationId, String environment) throws MalformedURLException {
        this.satelliteUrl = new URL(satelliteUrl);
        this.organizationId = organizationId;
        this.environment = environment;
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(DIRECT)
                .build();
    }

    public void updateSatelliteUrl(String satelliteUrl) throws MalformedURLException {
        if (satelliteUrl == null || satelliteUrl.isEmpty()) {
            return;
        }
        var url = new URL(satelliteUrl);
        if (url.getHost() != null && !url.getHost().isEmpty()) {
            this.satelliteUrl = url;
        }
    }

    public void updateOrganizationId(String organizationId) {
        this.organizationId = OrganizationId.requireValid(organizationId);
    }

    public void updateEnvironment(String environment) {
        this.environment = environment;
    }

    public String getEnvironment() {
        return this.environment;
    }

    public void sendHttpMessage(HttpMessage httpMessage) throws SatelliteMessageFailed, JsonProcessingException {
        if (organizationId == null || organizationId.isEmpty()) {
            throw new SatelliteMessageFailed("Organization ID is not set", (short) 400);
        }
        if (!OrganizationId.isValid(organizationId)) {
            throw new SatelliteMessageFailed(OrganizationId.validationMessage(organizationId), (short) 400);
        }
        // Read the URL snapshot once so a runtime change can't split host and port.
        URL base = this.satelliteUrl;
        String orgId = this.organizationId;
        var mapper = new ObjectMapper();
        var jsonBody = mapper.writeValueAsString(httpMessage);

        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(tracesUri(base))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("x-levo-organization-id", orgId)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
        } catch (URISyntaxException e) {
            throw new SatelliteMessageFailed("Invalid Satellite URL: " + e.getMessage(), (short) 400);
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new SatelliteMessageFailed(
                    "Failed to connect to Levo Satellite. " + e.getMessage(), (short) 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SatelliteMessageFailed(
                    "Failed to connect to Levo Satellite. Interrupted.", (short) 0);
        }

        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            String body = response.body() == null ? "" : response.body();
            throw new SatelliteMessageFailed(body, (short) status);
        }
    }

    /**
     * Satellite ingest is always {@code /1.0/ebpf/traces}. A path on the configured
     * URL is not part of the ingest route. Default ports are omitted so the Host
     * header stays {@code example.com}, not {@code example.com:443}.
     */
    static URI tracesUri(URL base) throws URISyntaxException {
        int port = base.getPort();
        if (port == base.getDefaultPort()) {
            port = -1;
        }
        return new URI(base.getProtocol(), null, base.getHost(), port, TRACES_PATH, null, null);
    }
}
