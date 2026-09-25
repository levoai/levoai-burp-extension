package ai.levo.exceptions;

public class SatelliteMessageFailed extends Exception {

    private final short statusCode;
    private final Long retryAfterMillis;

    public SatelliteMessageFailed(String message, short statusCode) {
        this(message, statusCode, null);
    }

    public SatelliteMessageFailed(String message, short statusCode, Long retryAfterMillis) {
        super(message);
        this.statusCode = statusCode;
        this.retryAfterMillis = retryAfterMillis;
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

}

