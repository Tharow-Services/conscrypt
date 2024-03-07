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
 * Cipher suites to metric mapping for metrics instrumentation.
 *
 * Must be in sync with frameworks/base/cmds/statsd/src/atoms.proto
 *
 * Ids are based on IANA's database of SSL/TLS cipher suites
 * @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */
@Internal
public enum CipherSuite {
    UNKNOWN_CIPHER_SUITE(0x00),

    // Supported but not enabled
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0x0B),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0x14),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x35),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0x09),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0x13),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x2F),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x0A),

    // TLSv1.2 cipher suites
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x9C),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x9D),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0x2F),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0x30),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0x2B),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0x2C),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xA9),
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xA8),

    // Pre-Shared Key (PSK) cipher suites
    TLS_PSK_WITH_AES_128_CBC_SHA(0x8C),
    TLS_PSK_WITH_AES_256_CBC_SHA(0x8D),
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0x35),
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0x36),
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256(0xAC),

    // TLS 1.3 cipher suites
    TLS_AES_128_GCM_SHA256(0x01),
    TLS_AES_256_GCM_SHA384(0x02),
    TLS_CHACHA20_POLY1305_SHA256(0x03),

    TLS_CIPHER_FAILED(0xFF),
    ;

    final short id;

    public int getId() {
        return this.id;
    }

    public static CipherSuite forName(String name) {
        if ("SSL_RSA_WITH_3DES_EDE_CBC_SHA".equals(name)) {
            // JCA StandardNames shenanigans.
            return TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        }
        try {
            return CipherSuite.valueOf(name);
        } catch (IllegalArgumentException e) {
            return CipherSuite.UNKNOWN_CIPHER_SUITE;
        }
    }

    private CipherSuite(int id) {
        this.id = (short) id;
    }
}