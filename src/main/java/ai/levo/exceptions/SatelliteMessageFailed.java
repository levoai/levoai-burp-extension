package ai.levo.exceptions;

public class SatelliteMessageFailed extends Exception {

    private final short statusCode;
    private final Long retryAfterMillis;
    /**
     * True only when the POST was not written to the network. Satellite publishes
     * every accepted body and does not dedupe trace ids, so a replay after an
     * ambiguous failure would store the exchange twice.
     */
    private final boolean safeToRetry;

    public SatelliteMessageFailed(String message, short statusCode) {
        this(message, statusCode, null, false);
    }

    public SatelliteMessageFailed(String message, short statusCode, Long retryAfterMillis) {
        this(message, statusCode, retryAfterMillis, false);
    }

    public SatelliteMessageFailed(String message, short statusCode, Long retryAfterMillis, boolean safeToRetry) {
        super(message);
        this.statusCode = statusCode;
        this.retryAfterMillis = retryAfterMillis;
        this.safeToRetry = safeToRetry;
    }

    public short getStatusCode() {
        return statusCode;
    }

    /**
     * @return delay requested by a {@code Retry-After} header, in milliseconds, or null
     */
    public Long getRetryAfterMillis() {
        return retryAfterMillis;
    }

    /**
     * @return true when retrying cannot duplicate a trace Satellite already stored
     */
    public boolean isSafeToRetry() {
        return safeToRetry;
    }

}

