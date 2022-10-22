package ai.levo;

import com.google.gson.annotations.SerializedName;

import java.util.Map;

/**
 * The HTTP message (request & response) model that's sent as an API call trace to Levo's Satellite service.
 */
public class HttpMessage {
    public static class Request {
        private String body;
        private Map<String, String> headers;

        /**
         * Flag indicating if the request body was truncated.
         */
        private boolean truncated;

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, String> headers) {
            this.headers = headers;
        }

        public boolean isTruncated() {
            return truncated;
        }

        public void setTruncated(boolean truncated) {
            this.truncated = truncated;
        }
    }

    public static class Response {
        private String body;
        private Map<String, String> headers;

        /**
         * Flag indicating if the response body was truncated.
         */
        private boolean truncated;

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public void setHeaders(Map<String, String> headers) {
            this.headers = headers;
        }

        public boolean isTruncated() {
            return truncated;
        }

        public void setTruncated(boolean truncated) {
            this.truncated = truncated;
        }
    }

    public static class Net {
        private String ip;
        private int port;

        public String getIp() {
            return ip;
        }

        public void setIp(String ip) {
            this.ip = ip;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }
    }

    private Request request;
    private Response response;

    /**
     * Metadata about the service which has received/sent the request. We'll use the default service name for Burp.
     */
    private Map<String, String> resource;

    @SerializedName("local_net")
    private Net localNet;

    @SerializedName("remote_net")
    private Net remoteNet;

    @SerializedName("trace_id")
    private String traceId;

    @SerializedName("span_id")
    private String spanId;

    @SerializedName("span_kind")
    private String spanKind;

    /**
     * Time taken by the request to be processed by the service.
     */
    @SerializedName("duration_ns")
    private long durationNs;

    /**
     * Current timestamp in nanoseconds (Unix time) when the request was sent.
     */
    @SerializedName("request_time_ns")
    private long requestTimeNs;

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public Response getResponse() {
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

    public Map<String, String> getResource() {
        return resource;
    }

    public void setResource(Map<String, String> resource) {
        this.resource = resource;
    }

    public Net getLocalNet() {
        return localNet;
    }

    public void setLocalNet(Net localNet) {
        this.localNet = localNet;
    }

    public Net getRemoteNet() {
        return remoteNet;
    }

    public void setRemoteNet(Net remoteNet) {
        this.remoteNet = remoteNet;
    }

    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public String getSpanId() {
        return spanId;
    }

    public void setSpanId(String spanId) {
        this.spanId = spanId;
    }

    public String getSpanKind() {
        return spanKind;
    }

    public void setSpanKind(String spanKind) {
        this.spanKind = spanKind;
    }

    public long getDurationNs() {
        return durationNs;
    }

    public void setDurationNs(long durationNs) {
        this.durationNs = durationNs;
    }

    public long getRequestTimeNs() {
        return requestTimeNs;
    }

    public void setRequestTimeNs(long requestTimeNs) {
        this.requestTimeNs = requestTimeNs;
    }
}
