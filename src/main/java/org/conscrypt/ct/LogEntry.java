/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.ct;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.conscrypt.OpenSSLX509Certificate;

/**
 * LogEntry structure, as defined by RFC6962 Section 3.2.
 */
public class LogEntry {
    private int type;
    private final byte[] certificate;
    // Only used when type is LOG_ENTRY_TYPE_PRECERT
    private final byte[] issuerKeyHash;

    private LogEntry(int type, byte[] certificate, byte[] issuerKeyHash) {
        this.type = type;
        this.certificate = certificate;
        if (issuerKeyHash != null && issuerKeyHash.length != 32) {
            throw new IllegalArgumentException("issuerKeyHash must be 32 bytes long");
        }
        this.issuerKeyHash = issuerKeyHash;
    }

    /**
     * @throws IllegalArgumentException if issuerKeyHash isn't 32 bytes
     */
    public static LogEntry createForPrecertificate(byte[] tbsCertificate, byte[] issuerKeyHash) {
        return new LogEntry(CTConstants.LOG_ENTRY_TYPE_PRECERT, tbsCertificate, issuerKeyHash);
    }

    public static LogEntry createForPrecertificate(OpenSSLX509Certificate leaf,
            OpenSSLX509Certificate issuer) throws CertificateEncodingException {
        try {
            byte[] issuerKey = issuer.getPublicKey().getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(issuerKey);
            byte[] issuerKeyHash = md.digest();

            OpenSSLX509Certificate preCert = leaf.withDeletedExtension(CTConstants.X509_SCT_LIST_OID);
            byte[] tbs = preCert.getTBSCertificate();

            return createForPrecertificate(tbs, issuerKeyHash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static LogEntry createForX509Certificate(byte[] x509Certificate) {
        return new LogEntry(CTConstants.LOG_ENTRY_TYPE_X509, x509Certificate, null);
    }

    public static LogEntry createForX509Certificate(X509Certificate cert)
            throws CertificateEncodingException {
        return createForX509Certificate(cert.getEncoded());
    }

    public int getType() {
        return type;
    }
    public byte[] getCertificate() {
        return certificate;
    }
    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    /**
     * TLS encode the structure.
     */
    public void encode(OutputStream output) throws SerializationException {
        SerializationUtils.writeNumber(output, type, CTConstants.LOG_ENTRY_TYPE_LENGTH);
        if (type == CTConstants.LOG_ENTRY_TYPE_PRECERT) {
            SerializationUtils.writeFixedBytes(output, issuerKeyHash);
        }
        SerializationUtils.writeVariableBytes(output, certificate,
                                              CTConstants.CERTIFICATE_LENGTH_BYTES);
    }
}

