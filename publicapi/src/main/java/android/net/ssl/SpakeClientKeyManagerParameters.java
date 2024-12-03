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

import javax.net.ssl.ManagerFactoryParameters;

/**
 * This class is used to provide specific data to a SPAKE2+ {@link
 * javax.net.ssl.KeyManagerFactory} for a client.
 */
public class SpakeClientKeyManagerParameters implements ManagerFactoryParameters {
    private byte[] clientIdentity;
    private byte[] serverIdentity;
    private byte[] clientPassword;
    private byte[] pakeContext;

    private SpakeClientKeyManagerParameters() {}

    /**
     * Builder for {@link SpakeClientKeyManagerParameters}.
     */
    public static class Builder {
        private byte[] clientIdentity;
        private byte[] serverIdentity;
        private byte[] clientPassword;
        private byte[] pakeContext;

        public Builder() {}

        /**
         * Sets the client's identity.
         *
         * @param identity The client's identity.
         * @return This builder.
         */
        @NonNull
        public Builder setClientIdentity(@NonNull byte[] identity) {
            clientIdentity = identity;
            return this;
        }

        /**
         * Sets the server's identity.
         *
         * @param identity The server's identity.
         * @return This builder.
         */
        @NonNull
        public Builder setServerIdentity(@NonNull byte[] identity) {
            serverIdentity = identity;
            return this;
        }

        /**
         * Sets the shared password.
         *
         * @param password The shared password.
         * @return This builder.
         */
        @NonNull
        public Builder setClientPassword(@NonNull byte[] password) {
            clientPassword = password;
            return this;
        }

        /**
         * Sets the PAKE context.
         *
         * @param context The PAKE context.
         * @return This builder.
         */
        @NonNull
        public Builder setPakeContext(@NonNull byte[] context) {
            pakeContext = context;
            return this;
        }

        /**
         * Builds the {@link SpakeClientKeyManagerParameters}.
         *
         * @return The built parameters.
         */
        @NonNull
        public SpakeClientKeyManagerParameters build() {
            requireNonNull(clientIdentity);
            requireNonNull(serverIdentity);
            requireNonNull(clientPassword);
            requireNonNull(pakeContext);

            SpakeClientKeyManagerParameters params = new SpakeClientKeyManagerParameters();

            params.clientIdentity = clientIdentity;
            params.serverIdentity = serverIdentity;
            params.clientPassword = clientPassword;
            params.pakeContext = pakeContext;

            return params;
        }
    }

    /**
     * Gets the client's identity.
     *
     * @return The client's identity.
     */
    public @NonNull byte[] getClientIdentity() {
        return clientIdentity;
    }

    /**
     * Gets the server's identity.
     *
     * @return The server's identity.
     */
    public @NonNull byte[] getServerIdentity() {
        return serverIdentity;
    }

    /**
     * Gets the client's password.
     *
     * @return The client's password.
     */
    public @NonNull byte[] getClientPassword() {
        return clientPassword;
    }

    /**
     * Gets the PAKE context.
     *
     * @return The PAKE context.
     */
    public @NonNull byte[] getPakeContext() {
        return pakeContext;
    }
}