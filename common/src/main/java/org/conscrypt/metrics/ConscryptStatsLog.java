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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * TODO(nikitai):
 **/
public class ConscryptStatsLog {
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    private static Class<?> c_statsEvent;
    private static Class<?> c_statsEvent_Builder;
    private static Class<?> c_statsLog;

    private static Method m_statsEvent__newBuilder;
    private static Method m_statsEvent_Builder__setAtomId;
    private static Method m_statsEvent_Builder__writeBoolean;
    private static Method m_statsEvent_Builder__writeInt;
    private static Method m_statsEvent_Builder__build;
    private static Method m_statsEvent_usePooledBuffer;
    private static Method m_statsLog__write;

    private static boolean classesLoaded;

    static {
        try {
            c_statsEvent = Class.forName("android.util.StatsEvent");
            m_statsEvent__newBuilder = c_statsEvent.getMethod("newBuilder");
            c_statsEvent_Builder = Class.forName("android.util.StatsEvent$Builder");
            m_statsEvent_Builder__setAtomId =
                    c_statsEvent_Builder.getMethod("setAtomId", int.class);
            m_statsEvent_Builder__writeBoolean =
                    c_statsEvent_Builder.getMethod("writeBoolean", boolean.class);
            m_statsEvent_Builder__writeInt = c_statsEvent_Builder.getMethod("writeInt", int.class);
            m_statsEvent_Builder__build = c_statsEvent_Builder.getMethod("build");
            m_statsEvent_usePooledBuffer = c_statsEvent_Builder.getMethod("usePooledBuffer");
            c_statsLog = Class.forName("android.util.StatsLog");
            m_statsLog__write = c_statsLog.getMethod("write", c_statsEvent);

            classesLoaded = true;
        } catch (Exception ignored) {
            classesLoaded = false;
        }
    }

    public static void write(
            int code, boolean success, int protocol, int cipherSuite, int duration) {
        if (!classesLoaded) {
            return;
        }
        try {
            Object builder = m_statsEvent__newBuilder.invoke(
                    c_statsEvent_Builder); // final StatsEvent.Builder builder =
                                           // StatsEvent.newBuilder();
            m_statsEvent_Builder__setAtomId.invoke(builder, code); // builder.setAtomId(code);
            m_statsEvent_Builder__writeBoolean.invoke(
                    builder, success); // builder.writeBoolean(arg1);
            m_statsEvent_Builder__writeInt.invoke(builder, protocol); // builder.writeInt(arg2);
            m_statsEvent_Builder__writeInt.invoke(builder, cipherSuite); // builder.writeInt(arg3);
            m_statsEvent_Builder__writeInt.invoke(builder, duration); // builder.writeInt(arg4);

            m_statsEvent_usePooledBuffer.invoke(builder); // builder.usePooledBuffer();
            Object statsEvent = m_statsEvent_Builder__build.invoke(builder);
            m_statsLog__write.invoke(null, statsEvent); // StatsLog.write(builder.build());
        } catch (Exception ignored) {
        }
    }
}
