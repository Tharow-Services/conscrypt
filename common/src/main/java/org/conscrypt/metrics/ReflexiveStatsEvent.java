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
 * Reflection wrapper around android.util.StatsEvent.
 */
@Internal
public class ReflexiveStatsEvent {
    private static OptionalMethod newBuilder;
    private static Class<?> c_statsEvent;

    static {
        try {
            c_statsEvent = Class.forName("android.util.StatsEvent");
        } catch (ClassNotFoundException ignored) {
        }
        newBuilder = new OptionalMethod(c_statsEvent, "newBuilder");
    }

    private Object statsEvent;

    private ReflexiveStatsEvent(Object statsEvent) {
        this.statsEvent = statsEvent;
    }

    public Object getStatsEvent() {
        return statsEvent;
    }

    public static ReflexiveStatsEvent.Builder newBuilder() {
        return new ReflexiveStatsEvent.Builder();
    }

    public static final class Builder {
        private static Class<?> c_statsEvent;
        private static Class<?> c_statsEvent_Builder;
        private static OptionalMethod setAtomId;
        private static OptionalMethod writeBoolean;
        private static OptionalMethod writeInt;
        private static OptionalMethod build;
        private static OptionalMethod usePooledBuffer;

        static {
            try {
                c_statsEvent = Class.forName("android.util.StatsEvent");
                c_statsEvent_Builder = Class.forName("android.util.StatsEvent$Builder");
            } catch (ClassNotFoundException ignored) {
            }
            newBuilder = new OptionalMethod(c_statsEvent, "newBuilder");
            setAtomId = new OptionalMethod(c_statsEvent_Builder, "setAtomId", int.class);
            writeBoolean = new OptionalMethod(c_statsEvent_Builder, "writeBoolean", boolean.class);
            writeInt = new OptionalMethod(c_statsEvent_Builder, "writeInt", int.class);
            build = new OptionalMethod(c_statsEvent_Builder, "build");
            usePooledBuffer = new OptionalMethod(c_statsEvent_Builder, "usePooledBuffer");
        }

        private Object builder;

        private Builder() {
            this.builder = newBuilder.invoke(null);
        }

        public Builder setAtomId(final int atomId) {
            setAtomId.invoke(this.builder, atomId);
            return this;
        }

        public Builder writeBoolean(final boolean value) {
            writeBoolean.invoke(this.builder, value);
            return this;
        }

        public Builder writeInt(final int value) {
            writeInt.invoke(this.builder, value);
            return this;
        }

        public void usePooledBuffer() {
            usePooledBuffer.invoke(this.builder);
        }

        public ReflexiveStatsEvent build() {
            Object statsEvent = build.invoke(this.builder);
            return new ReflexiveStatsEvent(statsEvent);
        }
    }
}