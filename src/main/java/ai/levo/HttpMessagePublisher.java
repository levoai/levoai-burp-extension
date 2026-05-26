package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.IRequestInfo;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Handles the HTTP messages that are received and sends them to Levo's Satellite.
 */
public class HttpMessagePublisher implements IExtensionStateListener {

    private static final String TWO_LINES_PATTERN = "\r\n\r\n";
    private static final String NEW_LINE_PATTERN = "\r\n";
    private static final String DEFAULT_SERVICE_NAME = "default";
    private static final String DEFAULT_ENVIRONMENT = "staging";
    private static final String CONTENT_TYPE_HEADER = "content-type";

    private static final List<String> ACCEPTED_CONTENT_TYPES = Arrays.asList(
            "application/json",
            "application/x-www-form-urlencoded",
            "application/pdf",
            "text/json",
            "text/plain"
    );
    // Don't send the response body for these content types
    private static final Set<String> DROP_CONTENT_OF_TYPES = Set.of("application/pdf");
    private static final String SERVICE_NAME_RESOURCE_KEY = "service_name";
    private static final String SENSOR_TYPE_KEY = "sensor_type";
    private static final String SENSOR_TYPE_VALUE = "BURP_EXTENSION";
    private static final String SENSOR_VERSION_KEY = "sensor_version";
    private static final String HOST_NAME_KEY = "host_name";
    private static final String ENVIRONMENT_KEY = "levo_env";

    // Immutable base resource map populated once at class load. Per-message env is layered on top.
    private static final Map<String, String> BASE_RESOURCE_MAP;

    static {
        String hostname = "unknown";
        String version = "unknown";
        try {
            var props = new Properties();
            props.load(HttpMessagePublisher.class.getResourceAsStream("/settings.properties"));
            version = props.getProperty("version", "unknown");
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (Exception ignored) {}
        BASE_RESOURCE_MAP = Map.of(
            SERVICE_NAME_RESOURCE_KEY, DEFAULT_SERVICE_NAME,
            SENSOR_TYPE_KEY, SENSOR_TYPE_VALUE,
            SENSOR_VERSION_KEY, version,
            HOST_NAME_KEY, hostname
        );
    }

    // Bounded publish queue. Sized so a brief Satellite hiccup doesn't lose data,
    // but a sustained outage doesn't grow the heap. DiscardOldestPolicy keeps recent traffic.
    private static final int PUBLISH_QUEUE_CAPACITY = 1024;
    private static final long SHUTDOWN_AWAIT_SECONDS = 5L;

    private final IBurpExtenderCallbacks callbacks;
    private final AlertWriter alertWriter;
    private final LevoSatelliteService satelliteService;
    private final ThreadPoolExecutor publishExecutor;
    private final AtomicLong droppedCount = new AtomicLong();

    public HttpMessagePublisher(LevoSatelliteService satelliteService, AlertWriter alertWriter, IBurpExtenderCallbacks callbacks) {
        this.alertWriter = alertWriter;
        this.callbacks = callbacks;
        this.satelliteService = satelliteService;
        this.publishExecutor = new ThreadPoolExecutor(
                1, 1,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(PUBLISH_QUEUE_CAPACITY),
                r -> {
                    Thread t = new Thread(r, "levo-satellite-publisher");
                    t.setDaemon(true);
                    return t;
                },
                this::onPublishRejected);
    }

    /**
     * Convert and queue an HTTP message for asynchronous delivery to Levo's Satellite.
     */
    void sendHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) {
        HttpMessage httpMessage = convertToHttpMessage(reqInfo, reqContent, statusCode, resContent);
        if (httpMessage == null) {
            return;
        }

        final String urlForLog = reqInfo.getUrl().getHost() + reqInfo.getUrl().getPath();

        publishExecutor.execute(() -> {
            try {
                satelliteService.sendHttpMessage(httpMessage);
                this.alertWriter.writeAlert("Sent the HTTP message for: " + urlForLog + " to Levo's Satellite.");
            } catch (SatelliteMessageFailed e) {
                this.alertWriter.writeAlert("Cannot send HTTP message to Levo. Status code(" + e.getStatusCode() + "): " + e.getMessage());
            } catch (JsonProcessingException e) {
                this.alertWriter.writeAlert("Cannot send HTTP message to Levo: Can't parse the HTTP message to JSON.");
            } catch (Exception e) {
                this.alertWriter.writeAlert("Cannot send HTTP message to Levo: " + e.getMessage());
            }
        });
    }

    /**
     * Drop-oldest rejection handler. Mirrors {@link ThreadPoolExecutor.DiscardOldestPolicy} but
     * increments {@link #droppedCount} and emits a throttled alert only when an eviction
     * actually happens — avoiding the race of inferring drops from a pre-execute size() check.
     */
    private void onPublishRejected(Runnable r, ThreadPoolExecutor exec) {
        if (exec.isShutdown()) {
            return;
        }
        exec.getQueue().poll();
        long total = droppedCount.incrementAndGet();
        // Throttle the alert: log on the first drop and then every 100th to avoid flooding.
        if (total == 1 || total % 100 == 0) {
            this.alertWriter.writeAlert("Levo Satellite publish queue full; dropped oldest messages (total dropped: " + total + ").");
        }
        exec.execute(r);
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

        return true;
    }

    private HttpMessage convertToHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) {
        HttpMessage.Request request = new HttpMessage.Request();
        request.setHeaders(convertHeadersToMap(reqInfo.getHeaders()));

        // Ignore if the request body isn't acceptable content type
        if (shouldDropMessage(request.getHeaders().get(CONTENT_TYPE_HEADER))) {
            this.alertWriter.writeAlert("Dropping because of content-type header not present");
            return null;
        }

        // Add the method and path separately in the headers.
        request.getHeaders().put(":method", reqInfo.getMethod());
        if (reqInfo.getUrl().getQuery() != null && !reqInfo.getUrl().getQuery().isEmpty()) {
            request.getHeaders().put(":path", reqInfo.getUrl().getPath() + "?" + reqInfo.getUrl().getQuery());
        } else {
            request.getHeaders().put(":path", reqInfo.getUrl().getPath());
        }

        String[] requestParts = callbacks.getHelpers().bytesToString(reqContent).split(TWO_LINES_PATTERN);
        if (requestParts.length > 1 && !requestParts[1].isEmpty()) {
            // Base64 encode the body.
            request.setBody(callbacks.getHelpers().base64Encode(requestParts[1]));
        } else {
            request.setBody("");
        }

        HttpMessage.Response response = new HttpMessage.Response();
        String[] responseParts = callbacks.getHelpers().bytesToString(resContent).split(TWO_LINES_PATTERN);

        // Create response headers from the first part of the response. Ignore the status line.
        String[] responseHeaders = responseParts[0].split(NEW_LINE_PATTERN);
        if (responseHeaders.length > 1) {
            List<String> headers = java.util.Arrays.asList(responseHeaders);
            headers = headers.subList(1, headers.size());
            response.setHeaders(convertHeadersToMap(headers));
        }

        // Ignore if the response isn't acceptable content type
        String contentType = response.getHeaders().get(CONTENT_TYPE_HEADER);
        if (shouldDropMessage(contentType)) {
            this.alertWriter.writeAlert("Dropping because content-type not being instrumented.");
            return null;
        }

        if (contentType != null && DROP_CONTENT_OF_TYPES.contains(contentType)) {
            alertWriter.writeAlert("Not sending response body for content-type: " + contentType + " to Levo.");
            response.setBody("");
        } else {
            if (responseParts.length > 1 && !responseParts[1].isEmpty()) {
                // Base64 encode the response body.
                response.setBody(callbacks.getHelpers().base64Encode(responseParts[1]));
            } else {
                response.setBody("");
            }
        }

        // Add the status code separately in the headers.
        response.getHeaders().put(":status", statusCode);

        // Build a fresh per-message resource map so concurrent traffic + an env change
        // can't last-writer-wins on a shared mutable map.
        Map<String, String> resourceMap = new HashMap<>(BASE_RESOURCE_MAP);
        String environment = this.satelliteService.getEnvironment();
        resourceMap.put(ENVIRONMENT_KEY,
                (environment != null && !environment.isEmpty()) ? environment : DEFAULT_ENVIRONMENT);

        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setRequest(request);
        httpMessage.setResponse(response);
        httpMessage.setResource(resourceMap);
        httpMessage.setSpanKind("SERVER");
        httpMessage.setTraceId(UUID.randomUUID().toString());
        httpMessage.setSpanId(UUID.randomUUID().toString());
        httpMessage.setRequestTimeNs(System.currentTimeMillis() * 1000000);
        return httpMessage;
    }

    private Map<String, String> convertHeadersToMap(List<String> headers) {
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
        publishExecutor.shutdown();
        try {
            if (!publishExecutor.awaitTermination(SHUTDOWN_AWAIT_SECONDS, TimeUnit.SECONDS)) {
                this.alertWriter.writeAlert("Levo Satellite publish queue did not drain in "
                        + SHUTDOWN_AWAIT_SECONDS + "s; forcing shutdown.");
                publishExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            publishExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
