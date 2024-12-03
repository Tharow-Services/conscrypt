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

import com.android.org.conscrypt.ByteArray;

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * This class is used to provide specific data to a SPAKE2+ {@link
 * javax.net.ssl.KeyManagerFactory} for a server.
 */
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public class SpakeServerKeyManagerParameters implements ManagerFactoryParameters {
    private Map<ByteArray, byte[]> passwords;
    private byte[] pakeContext;

    private SpakeServerKeyManagerParameters() {}

    /**
     * Builder for {@link SpakeServerKeyManagerParameters}.
     *
     * Before running {@link build}, the context must be set through {@link setPakeContex} and there
     * mustbe at least one mapping set through {@link addPasswordMapping}.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static class Builder {
        private Map<ByteArray, byte[]> passwords = new HashMap<>();
        private byte[] pakeContext;

        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        public Builder() {}

        /**
         * Adds a password mapping for a client and server identity pair.
         *
         * @param clientIdentity The client's identity.
         * @param serverIdentity The server's identity.
         * @param password The password to use for the client and server identities.
         * @return This builder.
         */
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        @NonNull
        public Builder addPasswordMapping(@NonNull byte[] clientIdentity,
                @NonNull byte[] serverIdentity, @NonNull byte[] password) {
            return addPasswordMapping(new SpakeIdentity(clientIdentity, serverIdentity), password);
        }

        /**
         * Adds a password mapping for a {@link SpakeIdentity}.
         *
         * @param spakeIdentity The combined identity of the client and server.
         * @param password The password to use for the given identity.
         * @return This builder.
         */
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        @NonNull
        public Builder addPasswordMapping(
                @NonNull SpakeIdentity spakeIdentity, @NonNull byte[] password) {
            requireNonNull(spakeIdentity, "The identity needs to be set");
            requireNonNull(password, "The password needs to be set");
            passwords.put(spakeIdentity.combineIdentities(), password);
            return this;
        }

        /**
         * Sets the PAKE context to use for the server.
         *
         * @param pakeContext The PAKE context to use.
         * @return This builder.
         */
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
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
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        @NonNull
        public SpakeServerKeyManagerParameters build() {
            if (passwords.isEmpty()) {
                throw new InvalidParameterException();
            }
            requireNonNull(pakeContext, "The context needs to be set");

            SpakeServerKeyManagerParameters params = new SpakeServerKeyManagerParameters();
            params.passwords = passwords;
            params.pakeContext = pakeContext;
            return params;
        }
    }

    /**
     * Gets the password for a client and server identity pair.
     *
     * @param clientIdentity The client's identity.
     * @param serverIdentity The server's identity.
     * @return The password, or null if no password is found.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @Nullable byte[] getPassword(
            @NonNull byte[] clientIdentity, @NonNull byte[] serverIdentity) {
        return getPassword(new SpakeIdentity(clientIdentity, serverIdentity));
    }

    /**
     * Gets the password for a {@link SpakeIdentity}.
     *
     * @param spakeIdentity The combined identity of the client and server.
     * @return The password, or null if no password is found.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @Nullable byte[] getPassword(@NonNull SpakeIdentity spakeIdentity) {
        return passwords.get(spakeIdentity.combineIdentities());
    }

    /**
     * Gets the PAKE context to use for the server.
     *
     * @return The PAKE context, or null if no context has been set.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public @NonNull byte[] getPakeContext() {
        return pakeContext;
    }
}
