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
    private final int version;
    private final byte[] logId;
    private final long timestamp;
    private final byte[] extensions;
    private final DigitallySigned signature;

    public SignedCertificateTimestamp(int version, byte[] logId,
                                      long timestamp, byte[] extensions,
                                      DigitallySigned signature) {
        this.version = version;
        this.logId = logId;
        this.timestamp = timestamp;
        this.extensions = extensions;
        this.signature = signature;
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

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(InputStream input)
            throws SerializationException {
        int version = SerializationUtils.readNumber(input, CTConstants.VERSION_LENGTH);
        if (version != CTConstants.SCT_VERSION_V1) {
            throw new SerializationException("Unsupported SCT version " + version);
        }

        try {
            return new SignedCertificateTimestamp(
                version,
                SerializationUtils.readFixedBytes(input, CTConstants.LOGID_LENGTH),
                SerializationUtils.readLong(input, CTConstants.TIMESTAMP_LENGTH),
                SerializationUtils.readVariableBytes(input, CTConstants.EXTENSIONS_LENGTH_BYTES),
                DigitallySigned.decode(input)
            );
        } catch (IllegalArgumentException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Decode a TLS encoded SignedCertificateTimestamp structure.
     */
    public static SignedCertificateTimestamp decode(byte[] input)
            throws SerializationException {
        return decode(new ByteArrayInputStream(input));
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public void encodeTBS(OutputStream output, LogEntry logEntry)
            throws SerializationException {
        SerializationUtils.writeNumber(output, version, CTConstants.VERSION_LENGTH);
        SerializationUtils.writeNumber(output, CTConstants.SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP,
                                               CTConstants.SIGNATURE_TYPE_LENGTH);
        SerializationUtils.writeNumber(output, timestamp, CTConstants.TIMESTAMP_LENGTH);
        logEntry.encode(output);
        SerializationUtils.writeVariableBytes(output, extensions, CTConstants.EXTENSIONS_LENGTH_BYTES);
    }

    /**
     * TLS encode the signed part of the SCT, as described by RFC6962 section 3.2.
     */
    public byte[] encodeTBS(LogEntry entry)
            throws SerializationException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        encodeTBS(output, entry);
        return output.toByteArray();
    }
}

