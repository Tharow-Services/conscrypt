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

import com.android.org.conscrypt.ArrayUtils;
import com.android.org.conscrypt.ByteArray;

import libcore.util.NonNull;

/**
 * {@code SpakeIdentity} represents the combined identity of both the client and server
 * involved in a SPAKE2+ exchange.
 *
 * <p>This class encapsulates the concatenation of the client and server identities,
 * ensuring that they are treated as a single unit for the purpose of the SPAKE2+ protocol.
 */
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public class SpakeIdentity {
    private final byte[] clientIdentity;
    private final byte[] serverIdentity;
    private ByteArray combined = null;

    /**
     * Constructs a new {@code SpakeIdentity} comprising of the client and server identities.
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
        this.clientIdentity = clientIdentity;
        this.serverIdentity = serverIdentity;
    }

    /**
     * Combines the client and server identities into a single {@link
     * com.android.org.conscrypt.ByteArray}.
     *
     * @return The combined identity as a ByteArray.
     * @hide
     */
    public ByteArray combineIdentities() {
        if (combined == null) {
            combined = new ByteArray(ArrayUtils.concat(clientIdentity, serverIdentity));
        }
        return combined;
    }

    /**
     * Returns the client identity as a byte array.
     *
     * @return The client identity.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @NonNull byte[] getClientIdentity() {
        return clientIdentity;
    }

    /**
     * Returns the server identity as a byte array.
     *
     * @return The server identity.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @NonNull byte[] getServerIdentity() {
        return serverIdentity;
    }
}
