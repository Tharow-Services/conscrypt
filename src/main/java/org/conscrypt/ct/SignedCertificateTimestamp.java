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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * SignedCertificateTimestamp structure, as defined by RFC6962 Section 3.2.
 */
public class SignedCertificateTimestamp {
    public static enum Origin {
        EMBEDDED,
        TLS_EXTENSION,
        OCSP_RESPONSE
    };

    private final int version;
    private final byte[] logId;
    private final long timestamp;
    private final byte[] extensions;
    private final DigitallySigned signature;

    // This is not encoded with the SCT
    // The verification process for SCTs depend on it
    private final Origin origin;

    public SignedCertificateTimestamp(int version, byte[] logId,
                                      long timestamp, byte[] extensions,
                                      DigitallySigned signature, Origin origin) {
        this.version = version;
        this.logId = logId;
        this.timestamp = timestamp;
        this.extensions = extensions;
        this.signature = signature;
        this.origin = origin;
    }

    public int getVersion() {
        return version;
    }
    public byte[] getLogID() {
        return logId;
    }
    public long getTimestamp() {
        return timestamp;
    }
    public byte[] getExtensions() {
        return extensions;
    }
    public DigitallySigned getSignature() {
        return signature;
    }
    public Origin getOrigin() {
        return origin;
    }

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
            throws SerializationException {
        int version = Serialization.readNumber(input, CTConstants.VERSION_LENGTH);
        if (version != CTConstants.SCT_VERSION_V1) {
            throw new SerializationException("Unsupported SCT version " + version);
        }

        return new SignedCertificateTimestamp(
            version,
            Serialization.readFixedBytes(input, CTConstants.LOGID_LENGTH),
            Serialization.readLong(input, CTConstants.TIMESTAMP_LENGTH),
            Serialization.readVariableBytes(input, CTConstants.EXTENSIONS_LENGTH_BYTES),
            DigitallySigned.decode(input),
            origin
        );
    }

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(byte[] input, Origin origin)
            throws SerializationException {
        return decode(new ByteArrayInputStream(input), origin);
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public void encodeTBS(OutputStream output, CertificateEntry certEntry)
            throws SerializationException {
        Serialization.writeNumber(output, version, CTConstants.VERSION_LENGTH);
        Serialization.writeNumber(output, CTConstants.SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP,
                                               CTConstants.SIGNATURE_TYPE_LENGTH);
        Serialization.writeNumber(output, timestamp, CTConstants.TIMESTAMP_LENGTH);
        certEntry.encode(output);
        Serialization.writeVariableBytes(output, extensions, CTConstants.EXTENSIONS_LENGTH_BYTES);
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public byte[] encodeTBS(CertificateEntry certEntry)
            throws SerializationException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        encodeTBS(output, certEntry);
        return output.toByteArray();
    }
}

