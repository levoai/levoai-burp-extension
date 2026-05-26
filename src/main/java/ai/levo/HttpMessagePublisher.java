package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.IRequestInfo;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Handles the HTTP messages that are received and sends them to Levo's Satellite.
 * <p>
 * Publishing happens on a dedicated worker thread so the proxy thread is never blocked
 * on the Satellite POST. If the queue fills up (Satellite is slow or unreachable) the
 * oldest pending message is dropped to keep proxy throughput stable.
 */
public class HttpMessagePublisher implements IExtensionStateListener {

    private static final String TWO_LINES_PATTERN = "\r\n\r\n";
    private static final String NEW_LINE_PATTERN = "\r\n";
    private static final String DEFAULT_SERVICE_NAME = "default";
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
    private static final String DEFAULT_ENVIRONMENT = "staging";

    // Bounded publish queue: tune for memory vs. drop rate. ~1k messages of typical
    // size is in the low MB range and keeps a healthy backlog without unbounded growth.
    private static final int PUBLISH_QUEUE_CAPACITY = 1000;
    // Time to wait for in-flight publishes to drain on extension unload.
    private static final long SHUTDOWN_TIMEOUT_SECONDS = 5L;

    /** Immutable subset of the resource map — values that never change at runtime. */
    private final Map<String, String> baseResource;


    private final IBurpExtenderCallbacks callbacks;

    /**
     * Ref on alert writer.
     */
    private final AlertWriter alertWriter;

    private final LevoSatelliteService satelliteService;

    private final ThreadPoolExecutor publishExecutor;

    /** Count of messages dropped due to a full publish queue. Reported on unload. */
    private final AtomicLong droppedMessageCount = new AtomicLong();

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
        this.baseResource = buildBaseResource();
        this.publishExecutor = new ThreadPoolExecutor(
                1, 1,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(PUBLISH_QUEUE_CAPACITY),
                r -> {
                    Thread t = new Thread(r, "levo-satellite-publisher");
                    t.setDaemon(true);
                    return t;
                },
                // Drop-oldest policy: when the queue is full, evict the head and enqueue
                // the new task. Keeps the most recent traffic flowing to the Satellite
                // rather than blocking the proxy thread.
                (r, exec) -> {
                    if (exec.isShutdown()) {
                        return;
                    }
                    exec.getQueue().poll();
                    droppedMessageCount.incrementAndGet();
                    exec.getQueue().offer(r);
                });
    }

    private static Map<String, String> buildBaseResource() {
        String hostname = "unknown";
        String version = "unknown";
        try {
            var props = new Properties();
            props.load(HttpMessagePublisher.class.getResourceAsStream("/settings.properties"));
            version = props.getProperty("version", "unknown");
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (Exception ignored) {}
        return Map.of(
                SERVICE_NAME_RESOURCE_KEY, DEFAULT_SERVICE_NAME,
                SENSOR_TYPE_KEY, SENSOR_TYPE_VALUE,
                SENSOR_VERSION_KEY, version,
                HOST_NAME_KEY, hostname);
    }

    /**
     * Send an HTTP message to Levo's Satellite.
     * <p>
     * The conversion runs on the caller's thread (so we don't retain Burp-managed
     * objects across threads), then the actual network send is enqueued on a worker.
     *
     * @param reqInfo    Details of the request to be processed.
     * @param reqContent Raw content of the request.
     */
    void sendHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent) {
        HttpMessage httpMessage = convertToHttpMessage(reqInfo, reqContent, statusCode, resContent);
        if (httpMessage == null) {
            return;
        }

        String requestUrl = reqInfo.getUrl().getHost() + reqInfo.getUrl().getPath();
        try {
            publishExecutor.execute(() -> publish(httpMessage, requestUrl));
        } catch (RejectedExecutionException e) {
            // Only happens after shutdown — silently drop.
            droppedMessageCount.incrementAndGet();
        }
    }

    private void publish(HttpMessage httpMessage, String requestUrl) {
        try {
            satelliteService.sendHttpMessage(httpMessage);
            this.alertWriter.writeAlert("Sent the HTTP message for: " + requestUrl + " to Levo's Satellite.");
        } catch (SatelliteMessageFailed e) {
            this.alertWriter.writeAlert("Cannot send HTTP message to Levo. Status code(" + e.getStatusCode() + "): " + e.getMessage());
        } catch (JsonProcessingException e) {
            this.alertWriter.writeAlert("Cannot send HTTP message to Levo: Can't parse the HTTP message to JSON.");
        } catch (Exception e) {
            // Defensive: a bug in conversion or transport must not kill the worker thread.
            this.alertWriter.writeAlert("Unexpected error publishing to Levo: " + e.getMessage());
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
            // Create a list from an array and remove the first element since that's status line.
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
                // Don't drop the message if the response body is empty.
                response.setBody("");
            }
        }

        // Add the status code separately in the headers.
        response.getHeaders().put(":status", statusCode);

        HttpMessage httpMessage = new HttpMessage();
        httpMessage.setRequest(request);
        httpMessage.setResponse(response);
        // Build the resource map fresh per message so a concurrent environment update
        // can never tag the wrong message (previously a shared static map was mutated
        // here, allowing last-writer-wins races).
        httpMessage.setResource(buildResource());
        httpMessage.setSpanKind("SERVER");
        httpMessage.setTraceId(UUID.randomUUID().toString());
        httpMessage.setSpanId(UUID.randomUUID().toString());
        httpMessage.setRequestTimeNs(System.currentTimeMillis() * 1000000);
        return httpMessage;
    }

    private Map<String, String> buildResource() {
        Map<String, String> resource = new HashMap<>(baseResource);
        String environment = this.satelliteService.getEnvironment();
        resource.put(ENVIRONMENT_KEY, (environment != null && !environment.isEmpty()) ? environment : DEFAULT_ENVIRONMENT);
        return resource;
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
        publishExecutor.shutdown();
        try {
            if (!publishExecutor.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                int discarded = publishExecutor.shutdownNow().size();
                this.alertWriter.writeAlert(
                        "Levo publisher shutdown timed out; discarded " + discarded + " queued messages.");
            }
        } catch (InterruptedException e) {
            publishExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        long dropped = droppedMessageCount.get();
        if (dropped > 0) {
            this.alertWriter.writeAlert("Levo publisher dropped " + dropped
                    + " message(s) due to back-pressure during this session.");
        }
    }
}
