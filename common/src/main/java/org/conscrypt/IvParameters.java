/*
 * Copyright (C) 2017 The Android Open Source Project
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

package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

/**
 * An implementation of {@link java.security.AlgorithmParameters} that contains only an IV.  The
 * primary (and only supported) encoding format is RAW.
 *
 * @hide
 */
@Internal
public class IvParameters extends AlgorithmParametersSpi {
    private byte[] iv;

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (!(algorithmParameterSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Only IvParameterSpec is supported");
        }
        iv = ((IvParameterSpec) algorithmParameterSpec).getIV().clone();
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        if (bytes.length < 2) {
            throw new IOException("Could not parse ASN.1 encoding");
        }
        if (bytes[0] != 0x04) {
            throw new IOException("Could not parse ASN.1 encoding");
        }
        int startIndex;
        int length;
        if ((bytes[1] & 0x80) == 0) {
            length = bytes[1];
            startIndex = 2;
        } else {
            int lenBytes = (bytes[1] & 0x0F);
            if ((lenBytes <= 0) || (4 < lenBytes)) {
                throw new IOException("Could not parse ASN.1 encoding");
            }
            startIndex = 1 + lenBytes;
            length = 0;
            for (int i = 0; i < lenBytes; i++) {
                length = length << 8;
                length |= Byte.toUnsignedInt(bytes[i + 1]);
            }
        }
        if (startIndex + length != bytes.length) {
            throw new IOException("Could not parse ASN.1 encoding");
        }
        iv = new byte[length];
        System.arraycopy(bytes, startIndex, iv, 0, length);
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if ((format == null) || (format.equals("ASN.1"))) {
            engineInit(bytes);
        } else if (format.equals("RAW")) {
            iv = bytes.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if (aClass != IvParameterSpec.class) {
            throw new InvalidParameterSpecException(
                    "Incompatible AlgorithmParametersSpec class: " + aClass);
        }
        return (T) new IvParameterSpec(iv);
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        byte[] encoded;
        if (iv.length < 128) {
            encoded = new byte[2 + iv.length];
            encoded[1] = (byte) iv.length;
        } else if (iv.length < (1 << 8)) {
            encoded = new byte[3 + iv.length];
            encoded[1] = (byte) 0x81;
            encoded[2] = (byte) iv.length;
        } else if (iv.length < (1 << 16)) {
            encoded = new byte[4 + iv.length];
            encoded[1] = (byte) 0x82;
            encoded[2] = (byte) (iv.length >> 8);
            encoded[3] = (byte) iv.length;
        } else if (iv.length < (1 << 24)) {
            encoded = new byte[5 + iv.length];
            encoded[1] = (byte) 0x83;
            encoded[2] = (byte) (iv.length >> 16);
            encoded[3] = (byte) (iv.length >> 8);
            encoded[4] = (byte) iv.length;
        } else {
            encoded = new byte[6 + iv.length];
            encoded[1] = (byte) 0x84;
            encoded[2] = (byte) (iv.length >> 24);
            encoded[3] = (byte) (iv.length >> 16);
            encoded[4] = (byte) (iv.length >> 8);
            encoded[5] = (byte) iv.length;
        }
        encoded[0] = 0x04;
        System.arraycopy(iv, 0, encoded, encoded.length - iv.length, iv.length);
        return encoded;
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if ((format == null) || (format.equals("ASN.1"))) {
            return engineGetEncoded();
        } else if (format.equals("RAW")) {
            return iv.clone();
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected String engineToString() {
        return "Conscrypt IV AlgorithmParameters";
    }

    public static class AES extends IvParameters {}
    public static class DES extends IvParameters {}
    public static class DESEDE extends IvParameters {}
}
