/*
 * Copyright (C) 2014 The Android Open Source Project
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

package org.conscrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class OpenSSLBIOSource extends OutputStream {
    private long ctx;

    private ByteBuffer byteBuffer;

    private OpenSSLBIOInputStream source;

    public OpenSSLBIOSource(ByteBuffer byteBuffer) {
        this.byteBuffer = byteBuffer;
        source = new OpenSSLBIOInputStream(new ByteBufferInputStream(byteBuffer));
        ctx = NativeCrypto.create_BIO_InputStream(source);
    }

    public long getContext() {
        return ctx;
    }

    @Override
    public void write(int oneByte) throws IOException {
        byteBuffer.put((byte) oneByte);
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        byteBuffer.put(buffer);
    }

    @Override
    public void write(byte[] buffer, int offset, int count) throws IOException {
        byteBuffer.put(buffer, offset, count);
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            NativeCrypto.BIO_free(ctx);
        } finally {
            super.finalize();
        }
    }

    private static class ByteBufferInputStream extends InputStream {
        private ByteBuffer source;

        public ByteBufferInputStream(ByteBuffer source) {
            this.source = source;
        }

        @Override
        public int read() throws IOException {
            return source.get();
        }

        @Override
        public int available() throws IOException {
            return source.limit() - source.position();
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            int originalPosition = source.position();
            source.get(buffer);
            return source.position() - originalPosition;
        }

        @Override
        public int read(byte[] buffer, int byteOffset, int byteCount) throws IOException {
            int toRead = Math.min(source.remaining(), byteCount);
            int originalPosition = source.position();
            source.get(buffer, byteOffset, toRead);
            return source.position() - originalPosition;
        }

        @Override
        public synchronized void reset() throws IOException {
            source.reset();
        }

        @Override
        public long skip(long byteCount) throws IOException {
            int originalPosition = source.position();
            source.position((int) (originalPosition + byteCount));
            return source.position() - originalPosition;
        }
    }
}
