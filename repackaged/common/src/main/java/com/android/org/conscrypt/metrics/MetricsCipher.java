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
package com.android.org.conscrypt.metrics;

import com.android.org.conscrypt.Internal;

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

    SHA512(0x0001),
    SHA384(0x0002),
    SHA256(0x0003),
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