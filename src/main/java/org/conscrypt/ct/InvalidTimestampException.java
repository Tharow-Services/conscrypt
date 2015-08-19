package org.conscrypt.ct;

public class InvalidTimestampException extends Exception {
    public InvalidTimestampException() {
    }

    public InvalidTimestampException(String message) {
        super(message);
    }

    public InvalidTimestampException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidTimestampException(Throwable cause) {
        super(cause);
    }
}

