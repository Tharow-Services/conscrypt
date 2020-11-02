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
 * Reflection wrapper around android.util.StatsLog.
 */
@Internal
public class ReflexiveStatsLog {
    private static Class<?> c_statsLog;
    private static Class<?> c_statsEvent;
    private static OptionalMethod write;

    static {
        try {
            c_statsLog = Class.forName("android.util.StatsLog");
            c_statsEvent = Class.forName("android.util.StatsEvent");
        } catch (ClassNotFoundException ignored) {
        }
        write = new OptionalMethod(c_statsLog, "write", c_statsEvent);
    }

    private ReflexiveStatsLog() {}

    public static void write(ReflexiveStatsEvent event) {
        write.invoke(null, event.getStatsEvent());
    }
}
