/*
 * Copyright (C) 2010 The Android Open Source Project
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

/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.conscrypt;

import java.nio.ByteBuffer;

/**
 * Utility methods for SSL packet processing. Copied from the Netty project.
 */
final class SSLUtils {

  /**
   * change cipher spec
   */
  private static final int SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;

  /**
   * alert
   */
  private static final int SSL_CONTENT_TYPE_ALERT = 21;

  /**
   * handshake
   */
  private static final int SSL_CONTENT_TYPE_HANDSHAKE = 22;

  /**
   * application data
   */
  private static final int SSL_CONTENT_TYPE_APPLICATION_DATA = 23;

  /**
   * the length of the ssl record header (in bytes)
   */
  static final int SSL_RECORD_HEADER_LENGTH = 5;

  /**
   * Return how much bytes can be read out of the encrypted data. Be aware that this method will not
   * increase the readerIndex of the given {@link ByteBuffer}.
   *
   * @param buffers The {@link ByteBuffer}s to read from. Be aware that they must have at least
   * {@link #SSL_RECORD_HEADER_LENGTH} bytes to read, otherwise it will throw an {@link
   * IllegalArgumentException}.
   * @return length The length of the encrypted packet that is included in the buffer. This will
   * return {@code -1} if the given {@link ByteBuffer} is not encrypted at all.
   * @throws IllegalArgumentException Is thrown if the given {@link ByteBuffer} has not at least
   * {@link #SSL_RECORD_HEADER_LENGTH} bytes to read.
   */
  static int getEncryptedPacketLength(ByteBuffer[] buffers, int offset) {
    ByteBuffer buffer = buffers[offset];

    // Check if everything we need is in one ByteBuffer. If so we can make use of the fast-path.
    if (buffer.remaining() >= SSL_RECORD_HEADER_LENGTH) {
      return getEncryptedPacketLength(buffer);
    }

    // We need to copy 5 bytes into a temporary buffer so we can parse out the packet length easily.
    ByteBuffer tmp = ByteBuffer.allocate(5);

    do {
      buffer = buffers[offset++].duplicate();
      if (buffer.remaining() > tmp.remaining()) {
        buffer.limit(buffer.position() + tmp.remaining());
      }
      tmp.put(buffer);
    } while (tmp.hasRemaining());

    // Done, flip the buffer so we can read from it.
    tmp.flip();
    return getEncryptedPacketLength(tmp);
  }

  private static int getEncryptedPacketLength(ByteBuffer buffer) {
    int packetLength = 0;
    int pos = buffer.position();
    // SSLv3 or TLS - Check ContentType
    boolean tls;
    switch (unsignedByte(buffer.get(pos))) {
      case SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
      case SSL_CONTENT_TYPE_ALERT:
      case SSL_CONTENT_TYPE_HANDSHAKE:
      case SSL_CONTENT_TYPE_APPLICATION_DATA:
        tls = true;
        break;
      default:
        // SSLv2 or bad data
        tls = false;
    }

    if (tls) {
      // SSLv3 or TLS - Check ProtocolVersion
      int majorVersion = unsignedByte(buffer.get(pos + 1));
      if (majorVersion == 3) {
        // SSLv3 or TLS
        packetLength = unsignedShort(buffer.getShort(pos + 3)) + SSL_RECORD_HEADER_LENGTH;
        if (packetLength <= SSL_RECORD_HEADER_LENGTH) {
          // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
          tls = false;
        }
      } else {
        // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
        tls = false;
      }
    }

    if (!tls) {
      // SSLv2 or bad data - Check the version
      int headerLength = (unsignedByte(buffer.get(pos)) & 0x80) != 0 ? 2 : 3;
      int majorVersion = unsignedByte(buffer.get(pos + headerLength + 1));
      if (majorVersion == 2 || majorVersion == 3) {
        // SSLv2
        if (headerLength == 2) {
          packetLength = (buffer.getShort(pos) & 0x7FFF) + 2;
        } else {
          packetLength = (buffer.getShort(pos) & 0x3FFF) + 3;
        }
        if (packetLength <= headerLength) {
          return -1;
        }
      } else {
        return -1;
      }
    }
    return packetLength;
  }

  private static short unsignedByte(byte b) {
    return (short) (b & 0xFF);
  }

  private static int unsignedShort(short s) {
    return s & 0xFFFF;
  }

  private SSLUtils() {
  }
}
