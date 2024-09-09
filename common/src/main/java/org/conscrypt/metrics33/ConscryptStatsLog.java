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

@Internal
public final class ConscryptStatsLog {
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    private ConscryptStatsLog() {}

    public static void write(int atomId, boolean success, int protocol, int cipherSuite,
            int duration, Source source, int[] uids) {
        GeneratedStatsLog.write(atomId, success, protocol, cipherSuite,
            duration, source.ordinal(), uids);
    }
}
