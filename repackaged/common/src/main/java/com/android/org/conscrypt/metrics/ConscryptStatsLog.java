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

import android.annotation.SuppressLint;
import com.android.org.conscrypt.metrics.GeneratedStatsLog;
import com.android.org.conscrypt.Internal;

/**
 * Reimplement with reflection calls the logging class,
 * generated by frameworks/statsd.
 * <p>
 * In case atom is changed, generate new wrapper with stats-log-api-gen
 * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
 * newEvent() method.
 * <p>
 * $ stats-log-api-gen \
 *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
 *   --module conscrypt \
 *   --javaPackage org.conscrypt.metrics \
 *   --javaClass ConscryptStatsLog
 * @hide This class is not part of the Android public SDK API
 **/
@Internal
public final class ConscryptStatsLog {
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    private ConscryptStatsLog() {}

    private static final Object sdkVersion;
    private static final boolean sdkVersionBiggerThan32;

    static {
        sdkVersion = getSdkVersion();
        sdkVersionBiggerThan32 = (sdkVersion != null) && ((int) sdkVersion > 32);
    }

    @SuppressLint("NewApi")
    public static void write(int atomId, boolean success, int protocol, int cipherSuite,
            int duration, Source source, int[] uids) {
        if (sdkVersionBiggerThan32) {
            GeneratedStatsLog.write(atomId, success, protocol, cipherSuite,
                duration, source.ordinal(), uids);
        } else {
            ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
                    atomId, success, protocol, cipherSuite, duration, source.ordinal(), uids);

            ReflexiveStatsLog.write(event);
        }
    }


    static Object getSdkVersion() {
        try {
            OptionalMethod getSdkVersion =
                    new OptionalMethod(Class.forName("dalvik.system.VMRuntime"),
                                        "getSdkVersion");
            return getSdkVersion.invokeStatic();
        } catch (ClassNotFoundException e) {
            return null;
        }
    }
}
