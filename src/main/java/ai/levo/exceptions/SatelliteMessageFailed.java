package ai.levo.exceptions;

public class SatelliteMessageFailed extends Exception {

    private final short statusCode;

    public SatelliteMessageFailed(String message, short statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public short getStatusCode() {
        return statusCode;
    }

}

