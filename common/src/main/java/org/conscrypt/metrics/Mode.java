/* GENERATED SOURCE. DO NOT MODIFY. */
/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2024 The Android Open Source Project
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
 * Mode to metric mapping for metrics instrumentation.
 *
 * Must be in sync with frameworks/base/cmds/statsd/src/atoms.proto
 */
@Internal
public enum Mode {
    NO_MODE(0x0000),
    CBC(0x0001),
    CTR(0x0002),
    ECB(0x0003),
    GCM(0x0004),
    GCM_SIV(0x0005),
    ;

    final int id;

    public int getId() {
        return this.id;
    }

    public static Mode forName(String name) {
        try {
            return Mode.valueOf(name);
        } catch (IllegalArgumentException e) {
            return Mode.UNKNOWN_CIPHER;
        }
    }

    private Mode(int id) {
        this.id = id;
    }
}