package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class LevoSatelliteService {

    private static final String TRACES_PATH = "/1.0/ebpf/traces";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
    /** Error responses are logged, not parsed. Keep only a short diagnostic. */
    static final int MAX_ERROR_BODY_BYTES = 1024;
    /**
     * Upper bound on a single retry wait. The publish worker is one thread, so a
     * multi-minute {@code Retry-After} would stall every other trace.
     */
    static final long MAX_RETRY_AFTER_MS = 5_000L;
    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.RFC_1123_DATE_TIME;

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

    /**
     * @deprecated The Burp callbacks are not used. Posts go directly to Satellite.
     *             Use {@link #create(String, String, String)}.
     */
    @Deprecated
    public static LevoSatelliteService create(String satelliteUrl, String organizationId, String environment,
                                              IBurpExtenderCallbacks callbacks) throws MalformedURLException {
        return create(satelliteUrl, organizationId, environment);
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

    /**
     * @deprecated The Burp callbacks are not used. Posts go directly to Satellite.
     *             Use {@link #LevoSatelliteService(String, String, String)}.
     */
    @Deprecated
    public LevoSatelliteService(IBurpExtenderCallbacks callbacks, String satelliteUrl, String organizationId,
                                String environment) throws MalformedURLException {
        this(satelliteUrl, organizationId, environment);
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

    /**
     * Posts the trace directly to Satellite.
     *
     * @return always {@code null}. Earlier versions returned the {@link IHttpRequestResponse}
     *         from Burp's {@code makeHttpRequest}. The direct client has no Burp message to
     *         return; the signature is unchanged so compiled callers keep linking.
     */
    public IHttpRequestResponse sendHttpMessage(HttpMessage httpMessage) throws SatelliteMessageFailed, JsonProcessingException {
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

        HttpResponse<InputStream> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new SatelliteMessageFailed(
                    "Failed to connect to Levo Satellite. " + e.getMessage(), (short) 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SatelliteMessageFailed(
                    "Failed to connect to Levo Satellite. Interrupted.", (short) 0);
        }

        int status = response.statusCode();
        try (InputStream body = response.body()) {
            if (status >= 200 && status < 300) {
                return null;
            }
            throw new SatelliteMessageFailed(
                    readErrorBody(body), (short) status, retryAfterMillis(response.headers()));
        } catch (IOException e) {
            throw new SatelliteMessageFailed(
                    "Failed to read Levo Satellite response. " + e.getMessage(), (short) status);
        }
    }

    private static String readErrorBody(InputStream body) throws IOException {
        if (body == null) {
            return "";
        }
        byte[] buf = body.readNBytes(MAX_ERROR_BODY_BYTES + 1);
        int length = Math.min(buf.length, MAX_ERROR_BODY_BYTES);
        String text = new String(buf, 0, length, StandardCharsets.UTF_8);
        if (buf.length > MAX_ERROR_BODY_BYTES) {
            return text + "...";
        }
        return text;
    }

    static Long retryAfterMillis(HttpHeaders headers) {
        Optional<String> raw = headers.firstValue("retry-after");
        if (raw.isEmpty()) {
            return null;
        }
        String text = raw.get().trim();
        if (text.isEmpty()) {
            return null;
        }
        try {
            long seconds = Long.parseLong(text);
            if (seconds < 0) {
                return null;
            }
            long millis = Math.multiplyExact(Math.min(seconds, MAX_RETRY_AFTER_MS / 1000L), 1000L);
            return Math.min(millis, MAX_RETRY_AFTER_MS);
        } catch (NumberFormatException ignored) {
            try {
                long when = ZonedDateTime.parse(text, HTTP_DATE).toInstant().toEpochMilli();
                long delay = when - System.currentTimeMillis();
                if (delay < 0) {
                    return 0L;
                }
                return Math.min(delay, MAX_RETRY_AFTER_MS);
            } catch (DateTimeParseException e) {
                return null;
            }
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
