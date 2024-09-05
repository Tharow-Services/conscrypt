/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2020 The Android Open Source Project
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
package org.conscrypt.metrics;

import org.conscrypt.Internal;

/**
 * Cipher to metric mapping for metrics instrumentation.
 *
 * Must be in sync with frameworks/base/cmds/statsd/src/atoms.proto
 *
 * Ids are based on IANA's database of SSL/TLS cipher suites
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public enum MetricsCipher {
    UNKNOWN_CIPHER(0x0000),

    RSA_OAEP_SHA512(0x0001),
    RSA_OAEP_SHA384(0x0002),
    RSA_OAEP_SHA256(0x0003),
    RSA_OAEP_SHA224(0x0004),
    RSA_OAEP_SHA1(0x0005),
    RSA_NO_PADDING(0x0006),
    RSA_PKCS1(0x0007),
    CHACHA20(0x008),
    ARC4(0x0009),
    AES_CBC(0x000A),
    AES_CTR(0x000B),
    AES_ECB(0x000C),
    AES_128_CBC(0x000D),
    AES_128_CTR(0x000E),
    AES_128_ECB(0x000F),
    AES_256_CBC(0x0010),
    AES_256_CTR(0x0011),
    AES_256_ECB(0x0012),
    DESEDE_CBC(0x0013),
    AES_128_GCM(0x0014),
    AES_256_GCM(0x0015),
    AES_128_GCM_SIV(0x0016),
    AES_256_GCM_SIV(0x0017),
    CHACHA20_POLY1305(0x0018),
    ;

    final int id;

    public int getId() {
        return this.id;
    }

    public static MetricsCipher forName(String name) {
        try {
            return MetricsCipher.valueOf(name);
        } catch (IllegalArgumentException e) {
            return MetricsCipher.UNKNOWN_CIPHER;
        }
    }

    private MetricsCipher(int id) {
        this.id = id;
    }
}