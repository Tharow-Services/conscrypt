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

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * This class is used to provide specific data to a SPAKE2+ {@link
 * javax.net.ssl.KeyManagerFactory} for a server.
 */
public class SpakeServerKeyManagerParameters implements ManagerFactoryParameters {
    private Map<byte[], byte[]> passwords;
    private byte[] pakeContext;

    private SpakeServerKeyManagerParameters() {}

    /**
     * Builder for {@link SpakeServerKeyManagerParameters}.
     */
    public static class Builder {
        private Map<byte[], byte[]> passwords = new HashMap<byte[], byte[]>();
        private byte[] pakeContext;

        public Builder() {}

        /**
         * Adds a password mapping for a client and server identity pair.
         *
         * @param clientIdentity The client's identity.
         * @param serverIdentity The server's identity.
         * @param password The password to use for the client and server identities.
         * @return This builder.
         */
        @NonNull
        public Builder addPasswordMapping(@NonNull byte[] clientIdentity,
                @NonNull byte[] serverIdentity, @NonNull byte[] password) {
            passwords.put(combineIdentities(clientIdentity, serverIdentity), password);
            return this;
        }

        /**
         * Sets the PAKE context to use for the server.
         *
         * @param pakeContext The PAKE context to use.
         * @return This builder.
         */
        @NonNull
        public Builder setPakeContext(@NonNull byte[] pakeContext) {
            this.pakeContext = pakeContext;
            return this;
        }

        /**
         * Builds the {@link SpakeServerKeyManagerParameters}.
         *
         * @return The built parameters.
         * @throws InvalidParameterException if no password mappings have been added.
         */
        @NonNull
        public SpakeServerKeyManagerParameters build() {
            if (passwords.isEmpty()) {
                throw new InvalidParameterException();
            }
            requireNonNull(pakeContext);

            SpakeServerKeyManagerParameters params = new SpakeServerKeyManagerParameters();
            params.passwords = passwords;
            params.pakeContext = pakeContext;
            return params;
        }
    }

    private static byte[] combineIdentities(byte[] clientIdentity, byte[] serverIdentity) {
        ByteBuffer identity = ByteBuffer.allocate(clientIdentity.length + serverIdentity.length);
        identity.put(clientIdentity);
        identity.put(serverIdentity);
        return identity.array();
    }

    /**
     * Gets the password for a client and server identity pair.
     *
     * @param clientIdentity The client's identity.
     * @param serverIdentity The server's identity.
     * @return The password, or null if no password is found.
     */
    public @Nullable byte[] getPassword(byte[] clientIdentity, byte[] serverIdentity) {
        return passwords.get(combineIdentities(clientIdentity, serverIdentity));
    }

    /**
     * Gets the PAKE context to use for the server.
     *
     * @return The PAKE context, or null if no context has been set.
     */
    public @Nullable byte[] getPakeContext() {
        return pakeContext;
    }
}
