package org.conscrypt.ct;

import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CTLogInfo {
    private final byte[] logId;
    private final PublicKey publicKey;
    private final String description;
    private final String url;

    public CTLogInfo(PublicKey publicKey, String description, String url) {
        try {
            this.logId = MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        this.publicKey = publicKey;
        this.description = description;
        this.url = url;
    }

    public byte[] getID() {
        return logId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getDescription() {
        return description;
    }

    public String getUrl() {
        return url;
    }
}

