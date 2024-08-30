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

import org.conscrypt.Internal;
import java.util.HashMap;
import java.util.Map;

@Internal
public final class CipherMetricsStatsLog {

    private Map<Integer, Integer> cipherMap = new HashMap<>();
    private int counter = 0;

    private CipherMetricsStatsLog() {};

    public void write(int cipherId, int uses) {
        counter++;
        if (cipherMap.containsKey(cipherId)) {
            cipherMap.put(cipherId, cipherMap.get(cipherId) + 1);
        } else {
            cipherMap.put(cipherId, 1);
        }
        if (counter % 20 == 0) {
            writeCipherMap();
            counter = 0;
        }
    }

    private void writeCipherMap() {
        for (Integer cipher : cipherMap.keySet()) {
            ConscryptStatsLog.write(ConscryptStatsLog.CONSCRYPT_CIPHER_USED,
                cipher, cipherMap.get(cipher));
        }
    }
}
