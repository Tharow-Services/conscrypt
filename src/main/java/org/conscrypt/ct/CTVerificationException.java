package org.conscrypt.ct;

import java.security.cert.CertificateException;

public class CTVerificationException extends CertificateException {
    public CTVerificationException() {
    }

    public CTVerificationException(String message) {
        super(message);
    }

    public CTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CTVerificationException(Throwable cause) {
        super(cause);
    }
}


