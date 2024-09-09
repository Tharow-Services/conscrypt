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

import java.util.concurrent.ExecutorService;
import org.conscrypt.Internal;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;

/**
 * @hide This class is not part of the Android public SDK API
 **/
@Internal
public final class CipherMetricsStatsLog {

    private Map <Integer, Integer> cipherMap = new HashMap<>();
    private int counter = 0;
    private final ExecutorService e;

    public CipherMetricsStatsLog() {
        e =
            new ThreadPoolExecutor(20, 50,
                                   0, TimeUnit.SECONDS,
                                   Executors.defaultThreadFactory());
    };

    public void write(int cipherId) {
      e.execute(new Runnable() {
            @Override
            public void run() {
              ConscryptStatsLog.write(ConscryptStatsLog.CONSCRYPT_CIPHER_USED,
                  cipherId, 1);
            }
        });
    }
}
