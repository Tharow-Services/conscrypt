/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.org.conscrypt;

import com.android.org.conscrypt.metrics.MetricsCipher;
import com.android.org.conscrypt.metrics.Mode;
import com.android.org.conscrypt.metrics.Padding;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

import javax.crypto.NoSuchPaddingException;

/**
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public abstract class OpenSSLEvpCipherDESEDE extends OpenSSLEvpCipher {
    private static final int DES_BLOCK_SIZE = 8;

    OpenSSLEvpCipherDESEDE(Mode mode, Padding padding) {
        super(mode, padding);
    }

    /**
     * @hide This class is not part of the Android public SDK API
     */
    public static class CBC extends OpenSSLEvpCipherDESEDE {
        CBC(Padding padding) {
            super(Mode.CBC, padding);
        }

        /**
         * @hide This class is not part of the Android public SDK API
         */
        public static class NoPadding extends CBC {
            public NoPadding() {
                super(Padding.NOPADDING);
                Platform.countCipherUsage(MetricsCipher.DESEDE.getId(),
                    Mode.CBC.getId(),
                    Padding.NO_PADDING.getId());
            }
        }

        /**
         * @hide This class is not part of the Android public SDK API
         */
        public static class PKCS5Padding extends CBC {
            public PKCS5Padding() {
                super(Padding.PKCS5PADDING);
                Platform.countCipherUsage(
                        MetricsCipher.DESEDE_CBC.getId(),
                        Mode.CBC.getId(),
                        Padding.PKCS5.getId());
            }
        }
    }

    @Override
    String getBaseCipherName() {
        return "DESede";
    }

    @Override
    String getCipherName(int keySize, Mode mode) {
        final String baseCipherName;
        if (keySize == 16) {
            baseCipherName = "des-ede";
        } else {
            baseCipherName = "des-ede3";
        }

        return baseCipherName + "-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 16 && keySize != 24) {
            throw new InvalidKeyException("key size must be 128 or 192 bits");
        }
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.CBC) {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode.toString());
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        switch (padding) {
            case NOPADDING:
            case PKCS5PADDING:
                return;
            default:
                throw new NoSuchPaddingException("Unsupported padding "
                        + padding.toString());
        }
    }

    @Override
    int getCipherBlockSize() {
        return DES_BLOCK_SIZE;
    }
}
