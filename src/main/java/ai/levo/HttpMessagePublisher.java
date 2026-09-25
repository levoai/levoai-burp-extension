package ai.levo;

import ai.levo.exceptions.SatelliteMessageFailed;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

/**
 * Handles the HTTP messages that are received and sends them to Levo's Satellite.
 */
public class HttpMessagePublisher implements IExtensionStateListener {

    private static final String DEFAULT_SERVICE_NAME = "default";
    private static final String DEFAULT_ENVIRONMENT = "staging";
    private static final String CONTENT_TYPE_HEADER = "content-type";

    private static final Set<String> ACCEPTED_CONTENT_TYPES = Set.of(
            "application/json",
            "application/x-www-form-urlencoded",
            "application/pdf",
            "text/json",
            "text/plain",
            "application/xml",
            "text/xml",
            "application/soap+xml",
            "application/problem+json",
            "application/vnd.api+json",
            "application/hal+json",
            "application/ld+json",
            "application/scim+json",
            "application/merge-patch+json"
    );
    // Don't send the response body for these content types
    private static final String PDF_MEDIA_TYPE = "application/pdf";
    private static final int SATELLITE_SEND_ATTEMPTS = 2;
    /**
     * Largest raw body that still shows up in a portal sample. Satellite's HAR
     * export blanks a body once its base64 form reaches 128KB
     * ({@code levoai_e7s.utils.har} {@code MAX_*_BODY_SIZE}). 98,301 raw bytes
     * encode to 131,068 base64 characters, just under that cap.
     */
    static final int MAX_RAW_BODY_BYTES = 98_301;
    /** Base64 body text retained by tasks waiting on the single publish worker. */
    static final long MAX_QUEUED_BODY_BYTES = 8L * 1024 * 1024;
    static final long RETRY_BASE_DELAY_MS = 200L;
    static final int RETRY_JITTER_BOUND_MS = 100;
    static final long QUEUE_DROP_LOG_INTERVAL_NS =
            TimeUnit.MILLISECONDS.toNanos(AlertWriter.RATE_LIMIT_WINDOW_MS);
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
    private final Pause pause;
    private final LongSupplier nanoTime;
    private final IntSupplier jitter;
    private final AtomicLong droppedCount = new AtomicLong();
    private final AtomicLong lastQueueDropLogAtNs = new AtomicLong();
    private final AtomicLong queuedBodyBytes = new AtomicLong();

    @FunctionalInterface
    interface Pause {
        void pause(long millis) throws InterruptedException;
    }

    public HttpMessagePublisher(LevoSatelliteService satelliteService, AlertWriter alertWriter, IBurpExtenderCallbacks callbacks) {
        this(satelliteService, alertWriter, callbacks,
                Thread::sleep,
                System::nanoTime,
                () -> ThreadLocalRandom.current().nextInt(RETRY_JITTER_BOUND_MS));
    }

    HttpMessagePublisher(LevoSatelliteService satelliteService, AlertWriter alertWriter, IBurpExtenderCallbacks callbacks,
                         Pause pause, LongSupplier nanoTime, IntSupplier jitter) {
        this.alertWriter = alertWriter;
        this.callbacks = callbacks;
        this.satelliteService = satelliteService;
        this.pause = pause;
        this.nanoTime = nanoTime;
        this.jitter = jitter;
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
     * Bodies are sliced with {@link IRequestInfo#getBodyOffset()} and
     * {@link IResponseInfo#getBodyOffset()} so a blank line inside an XML or gRPC
     * payload is part of the body.
     */
    void sendHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode, byte[] resContent,
                         IResponseInfo resInfo) {
        HttpMessage httpMessage = convertToHttpMessage(reqInfo, reqContent, statusCode, resContent, resInfo);
        if (httpMessage == null) {
            return;
        }

        final String urlForLog = reqInfo.getUrl().getHost() + reqInfo.getUrl().getPath();
        long bytes = retainedBodyBytes(httpMessage);
        PublishTask task = new PublishTask(httpMessage, urlForLog, bytes);
        if (!tryReserve(bytes)) {
            noteDrop("Levo Satellite publish queue is over its byte budget; dropped a message");
            return;
        }
        publishExecutor.execute(task);
    }

    private void deliverToSatellite(HttpMessage httpMessage, String urlForLog) {
        // Re-check the send-enabled flag here so messages enqueued while sending was
        // enabled are NOT exfiltrated after the user disables "Send traffic to Levo".
        // The listener stops enqueuing immediately on toggle-off, but tasks already in
        // the queue would otherwise still execute.
        //
        // Satellite's /1.0/ebpf/traces handler publishes every POST and does not dedupe
        // trace_id or span_id. Retry only when the post was never written, so a second
        // attempt cannot store the same exchange again. An HTTP status, including 429
        // and 5xx, means something already accepted the body.
        Exception lastFailure = null;
        for (int attempt = 0; attempt < SATELLITE_SEND_ATTEMPTS; attempt++) {
            if (!ConfigMenu.IS_SENDING_ENABLED) {
                return;
            }
            try {
                satelliteService.sendHttpMessage(httpMessage);
                this.alertWriter.writeInfo("Sent the HTTP message for: " + urlForLog + " to Levo's Satellite.");
                return;
            } catch (Exception e) {
                lastFailure = e;
                // Unload interrupts the worker. A second attempt would run during shutdown.
                if (Thread.currentThread().isInterrupted()) {
                    return;
                }
                boolean moreAttempts = attempt + 1 < SATELLITE_SEND_ATTEMPTS;
                if (!moreAttempts || !isRetryable(e)) {
                    break;
                }
                try {
                    pause.pause(retryDelayMillis(attempt, e));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        logSendFailure(lastFailure);
    }

    private static boolean isRetryable(Exception e) {
        return e instanceof SatelliteMessageFailed && ((SatelliteMessageFailed) e).isSafeToRetry();
    }

    private long retryDelayMillis(int attempt, Exception failure) {
        if (failure instanceof SatelliteMessageFailed) {
            Long retryAfter = ((SatelliteMessageFailed) failure).getRetryAfterMillis();
            if (retryAfter != null) {
                long delay = Math.max(0L, retryAfter);
                return Math.min(delay, LevoSatelliteService.MAX_RETRY_AFTER_MS);
            }
        }
        long exponential = RETRY_BASE_DELAY_MS << attempt;
        int spread = Math.max(0, jitter.getAsInt());
        return exponential + spread;
    }

    private void logSendFailure(Exception e) {
        if (!ConfigMenu.IS_SENDING_ENABLED || e == null) {
            return;
        }
        if (e instanceof SatelliteMessageFailed) {
            SatelliteMessageFailed failed = (SatelliteMessageFailed) e;
            this.alertWriter.writeErrorRateLimited(
                    "send-failed:" + failed.getStatusCode(),
                    "Sending to Levo is enabled, but the trace could not be delivered to Satellite. Status code("
                            + failed.getStatusCode() + "): " + failed.getMessage());
        } else if (e instanceof JsonProcessingException) {
            this.alertWriter.writeErrorRateLimited(
                    "send-failed:json",
                    "Sending to Levo is enabled, but the trace could not be delivered to Satellite: Can't parse the HTTP message to JSON.");
        } else {
            this.alertWriter.writeErrorRateLimited(
                    "send-failed:generic",
                    "Sending to Levo is enabled, but the trace could not be delivered to Satellite: " + e.getMessage());
        }
    }

    /**
     * Drop-oldest rejection handler. Behaviorally equivalent to
     * {@link ThreadPoolExecutor.DiscardOldestPolicy} but (a) only increments
     * {@link #droppedCount} on an actual eviction, and (b) loops on {@code poll()+offer()}
     * instead of recursing through {@code exec.execute(r)}, so a queue that refills under
     * high contention cannot grow the call stack and a shutdown between the initial check
     * and the retry cannot trigger a misleading "queue full" alert.
     */
    private void onPublishRejected(Runnable r, ThreadPoolExecutor exec) {
        BlockingQueue<Runnable> q = exec.getQueue();
        while (!exec.isShutdown()) {
            Runnable evicted = q.poll();
            if (evicted instanceof PublishTask) {
                ((PublishTask) evicted).release();
                noteDrop("Levo Satellite publish queue full; dropped oldest messages");
            }
            if (q.offer(r)) {
                return;
            }
            // Another producer refilled the queue between poll() and offer() — loop and drop another.
        }
        if (r instanceof PublishTask) {
            ((PublishTask) r).release();
        }
    }

    /**
     * Log the first drop, every 100th drop, and at least once per
     * {@link #QUEUE_DROP_LOG_INTERVAL_NS} while drops continue. Elapsed time comes
     * from {@link #nanoTime}, so a wall-clock rollback cannot suppress the warning.
     */
    private void noteDrop(String messagePrefix) {
        long total = droppedCount.incrementAndGet();
        long now = nanoTime.getAsLong();
        long last = lastQueueDropLogAtNs.get();
        boolean milestone = total == 1 || total % 100 == 0;
        boolean windowElapsed = now - last >= QUEUE_DROP_LOG_INTERVAL_NS;
        if ((milestone || windowElapsed) && lastQueueDropLogAtNs.compareAndSet(last, now)) {
            this.alertWriter.writeInfo(messagePrefix + " (total dropped: " + total + ").");
        }
    }

    private boolean tryReserve(long bytes) {
        if (bytes < 0 || bytes > MAX_QUEUED_BODY_BYTES) {
            return false;
        }
        while (true) {
            long current = queuedBodyBytes.get();
            if (current > MAX_QUEUED_BODY_BYTES - bytes) {
                return false;
            }
            if (queuedBodyBytes.compareAndSet(current, current + bytes)) {
                return true;
            }
        }
    }

    /**
     * Returns the current count of dropped messages due to queue overflow.
     * Exposed for testing.
     */
    long getDroppedCount() {
        return droppedCount.get();
    }

    /**
     * Returns the publish executor for testing purposes.
     * Exposed for testing.
     */
    ThreadPoolExecutor getPublishExecutor() {
        return publishExecutor;
    }

    /**
     * A missing Content-Type is kept. Comparison is on the media type only, so
     * {@code Application/JSON; charset=UTF-8} matches {@code application/json}.
     * GraphQL is accepted only as {@code application/graphql}, a type that starts
     * with {@code application/graphql+} or {@code application/graphql-}, or
     * {@code application/vnd.graphql+json}. The {@code application/grpc} family
     * ({@code application/grpc}, {@code application/grpc+…}, {@code application/grpc-…})
     * is accepted along with {@link #ACCEPTED_CONTENT_TYPES}.
     */
    static boolean shouldDropContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        String mediaType = mediaTypeKey(contentType);
        if ("(missing)".equals(mediaType)) {
            return true;
        }
        if (isAcceptedGraphql(mediaType)) {
            return false;
        }
        if ("application/grpc".equals(mediaType)
                || mediaType.startsWith("application/grpc+")
                || mediaType.startsWith("application/grpc-")) {
            return false;
        }
        return !ACCEPTED_CONTENT_TYPES.contains(mediaType);
    }

    private static boolean isAcceptedGraphql(String mediaType) {
        return "application/graphql".equals(mediaType)
                || mediaType.startsWith("application/graphql+")
                || mediaType.startsWith("application/graphql-")
                || "application/vnd.graphql+json".equals(mediaType);
    }

    private void logDroppedContentType(String side, String contentType) {
        String display = (contentType == null || contentType.isBlank()) ? "(missing)" : contentType;
        String key = "drop-" + side + ":" + mediaTypeKey(contentType);
        this.alertWriter.writeInfoRateLimited(key,
                "Dropping because " + side + " content-type '" + display + "' is not instrumented");
    }

    private static String mediaTypeKey(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "(missing)";
        }
        int semicolon = contentType.indexOf(';');
        String mediaType = semicolon >= 0 ? contentType.substring(0, semicolon) : contentType;
        return mediaType.trim().toLowerCase(Locale.ROOT);
    }

    private HttpMessage convertToHttpMessage(IRequestInfo reqInfo, byte[] reqContent, String statusCode,
                                             byte[] resContent, IResponseInfo resInfo) {
        HttpMessage.Request request = new HttpMessage.Request();
        request.setHeaders(convertHeadersToMap(reqInfo.getHeaders()));

        // Ignore if the request body isn't acceptable content type
        String requestContentType = request.getHeaders().get(CONTENT_TYPE_HEADER);
        if (shouldDropContentType(requestContentType)) {
            logDroppedContentType("request", requestContentType);
            return null;
        }

        // Add the method and path separately in the headers.
        request.getHeaders().put(":method", reqInfo.getMethod());
        if (reqInfo.getUrl().getQuery() != null && !reqInfo.getUrl().getQuery().isEmpty()) {
            request.getHeaders().put(":path", reqInfo.getUrl().getPath() + "?" + reqInfo.getUrl().getQuery());
        } else {
            request.getHeaders().put(":path", reqInfo.getUrl().getPath());
        }

        EncodedBody requestBody = encodeBody(reqContent, reqInfo.getBodyOffset());
        request.setBody(requestBody.base64);
        request.setTruncated(requestBody.truncated);

        HttpMessage.Response response = new HttpMessage.Response();
        response.setHeaders(new HashMap<>());
        List<String> rawResponseHeaders = resInfo == null ? null : resInfo.getHeaders();
        if (rawResponseHeaders != null && rawResponseHeaders.size() > 1) {
            response.setHeaders(convertHeadersToMap(rawResponseHeaders.subList(1, rawResponseHeaders.size())));
        }

        // Ignore if the response isn't acceptable content type
        Map<String, String> responseHeadersMap = response.getHeaders();
        String contentType = responseHeadersMap == null ? null : responseHeadersMap.get(CONTENT_TYPE_HEADER);
        if (shouldDropContentType(contentType)) {
            logDroppedContentType("response", contentType);
            return null;
        }

        if (PDF_MEDIA_TYPE.equals(mediaTypeKey(contentType))) {
            alertWriter.writeInfo("Not sending response body for content-type: " + contentType + " to Levo.");
            response.setBody("");
            response.setTruncated(false);
        } else {
            int responseOffset = resInfo == null ? (resContent == null ? 0 : resContent.length) : resInfo.getBodyOffset();
            EncodedBody responseBody = encodeBody(resContent, responseOffset);
            response.setBody(responseBody.base64);
            response.setTruncated(responseBody.truncated);
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

    private EncodedBody encodeBody(byte[] message, int bodyOffset) {
        if (message == null || bodyOffset < 0 || bodyOffset >= message.length) {
            return EncodedBody.EMPTY;
        }
        int available = message.length - bodyOffset;
        boolean truncated = available > MAX_RAW_BODY_BYTES;
        int length = truncated ? MAX_RAW_BODY_BYTES : available;
        byte[] body = Arrays.copyOfRange(message, bodyOffset, bodyOffset + length);
        String encoded = callbacks.getHelpers().base64Encode(body);
        if (encoded == null) {
            encoded = "";
        }
        return new EncodedBody(encoded, truncated);
    }

    private static long retainedBodyBytes(HttpMessage message) {
        return textLength(message.getRequest() == null ? null : message.getRequest().getBody())
                + textLength(message.getResponse() == null ? null : message.getResponse().getBody());
    }

    private static long textLength(String value) {
        return value == null ? 0L : value.length();
    }

    private Map<String, String> convertHeadersToMap(List<String> headers) {
        Map<String, String> headersMap = new HashMap<>();
        if (headers == null) {
            return headersMap;
        }
        for (String header : headers) {
            String[] headerParts = header.split(":", 2);
            if (headerParts.length == 2) {
                headersMap.put(headerParts[0].trim().toLowerCase(Locale.ROOT), headerParts[1].trim());
            }
        }

        return headersMap;
    }

    @Override
    public void extensionUnloaded() {
        publishExecutor.shutdown();
        try {
            if (!publishExecutor.awaitTermination(SHUTDOWN_AWAIT_SECONDS, TimeUnit.SECONDS)) {
                this.alertWriter.writeInfo("Levo Satellite publish queue did not drain in "
                        + SHUTDOWN_AWAIT_SECONDS + "s; forcing shutdown.");
                publishExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            publishExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private final class PublishTask implements Runnable {
        private final HttpMessage httpMessage;
        private final String urlForLog;
        private final long bytes;
        private final AtomicBoolean released = new AtomicBoolean();

        private PublishTask(HttpMessage httpMessage, String urlForLog, long bytes) {
            this.httpMessage = httpMessage;
            this.urlForLog = urlForLog;
            this.bytes = bytes;
        }

        @Override
        public void run() {
            try {
                deliverToSatellite(httpMessage, urlForLog);
            } finally {
                release();
            }
        }

        private void release() {
            if (released.compareAndSet(false, true)) {
                queuedBodyBytes.addAndGet(-bytes);
            }
        }
    }

    private static final class EncodedBody {
        private static final EncodedBody EMPTY = new EncodedBody("", false);

        private final String base64;
        private final boolean truncated;

        private EncodedBody(String base64, boolean truncated) {
            this.base64 = base64;
            this.truncated = truncated;
        }
    }
}
