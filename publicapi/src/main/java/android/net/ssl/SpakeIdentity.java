/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.net.ssl;

import static java.util.Objects.requireNonNull;

import android.annotation.FlaggedApi;

import libcore.util.NonNull;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * {@code SpakeIdentity} represents the combined identity of both the client and server
 * involved in a SPAKE2+ exchange.
 *
 * <p>This class encapsulates the concatenation of the client and server identities,
 * ensuring that they are treated as a single unit for the purpose of the SPAKE2+ protocol.
 */
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public class SpakeIdentity {
    private final byte[] identity;

    /**
     * Constructs a new {@code SpakeIdentity} by combining the client and server identities.
     *
     * @param clientIdentity The identity of the client.
     * @param serverIdentity The identity of the server.
     * @throws NullPointerException if either {@code clientIdentity} or {@code serverIdentity} is
     *         null.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public SpakeIdentity(@NonNull byte[] clientIdentity, @NonNull byte[] serverIdentity) {
        requireNonNull(clientIdentity, "Client identity needs to be set");
        requireNonNull(serverIdentity, "Server identity needs to be set");
        identity = combineIdentities(clientIdentity, serverIdentity);
    }

    /**
     * Combines the client and server identities into a single byte array.
     *
     * @param clientIdentity The identity of the client.
     * @param serverIdentity The identity of the server.
     * @return The combined identity as a byte array.
     */
    private static byte[] combineIdentities(byte[] clientIdentity, byte[] serverIdentity) {
        ByteBuffer identity = ByteBuffer.allocate(clientIdentity.length + serverIdentity.length);
        identity.put(clientIdentity);
        identity.put(serverIdentity);
        return identity.array();
    }

    /**
     * Returns the combined identity as a byte array.
     *
     * @return The combined identity.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @NonNull byte[] getIdentity() {
        return identity;
    }

    /**
     * Compares this {@code SpakeIdentity} to the specified object.
     *
     * <p>The result is {@code true} if and only if the argument is not {@code null}
     * and is a {@code SpakeIdentity} object with the same combined identity byte array
     * as this object.
     *
     * @param o The object to compare this {@code SpakeIdentity} against.
     * @return {@code true} if the given object represents a {@code SpakeIdentity}
     *         equivalent to this object, {@code false} otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        SpakeIdentity that = (SpakeIdentity) o;
        return Arrays.equals(identity, that.identity);
    }

    /**
     * Returns a hash code for this {@code SpakeIdentity}.
     *
     * <p>The hash code is computed based on the contents of the combined identity byte array.
     *
     * @return A hash code value for this object.
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(identity);
    }
}
