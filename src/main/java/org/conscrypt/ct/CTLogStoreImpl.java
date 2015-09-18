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

import java.util.Arrays;

public class CTLogStoreImpl implements CTLogStore {
    private CTLogInfo[] knownLogs;
    public CTLogStoreImpl() {
        // Lazy loaded by getKnownLog
        knownLogs = null;
    }

    public CTLogStoreImpl(CTLogInfo[] knownLogs) {
        this.knownLogs = knownLogs;
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        if (knownLogs == null) {
            knownLogs = KnownLogs.getKnownLogs();
        }
        for (CTLogInfo log: knownLogs) {
            if (Arrays.equals(logId, log.getID())) {
                return log;
            }
        }
        return null;
    }
}
