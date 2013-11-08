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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class OpenSSLBIOSink extends InputStream {
    private long ctx;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int position;

    public OpenSSLBIOSink() {
        ctx = NativeCrypto.create_BIO_OutputStream(buffer);
    }

    @Override
    public int available() {
        return buffer.size() - position;
    }

    @Override
    public int read() throws IOException {
        byte[] singleByte = new byte[1];
        int numRead = read(singleByte, 0, 1);
        if (numRead != 1) {
            return numRead;
        }
        return singleByte[0];
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    @Override
    public int read(byte[] outBuf, int byteOffset, int byteCount) throws IOException {
        int maxLength = Math.min(available(), byteCount);
        byte[] array = buffer.toByteArray();
        System.arraycopy(array, position, outBuf, byteOffset, maxLength);
        position += maxLength;
        if (position == buffer.size()) {
            reset();
        }
        return maxLength;
    }

    @Override
    public synchronized void reset() {
        buffer.reset();
        position = 0;
    }

    @Override
    public long skip(long byteCount) {
        int maxLength = Math.min(available(), (int) byteCount);
        position += maxLength;
        if (position == buffer.size()) {
            reset();
        }
        return maxLength;
    }

    public long getContext() {
        return ctx;
    }

    public byte[] toByteArray() {
        return buffer.toByteArray();
    }

    public int position() {
        return position;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            NativeCrypto.BIO_free(ctx);
        } finally {
            super.finalize();
        }
    }
}
