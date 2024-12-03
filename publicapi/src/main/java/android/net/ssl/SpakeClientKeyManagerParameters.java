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

import javax.net.ssl.ManagerFactoryParameters;

/**
 * This class is used to provide specific data to a SPAKE2+ {@link
 * javax.net.ssl.KeyManagerFactory} for a client.
 */
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public final class SpakeClientKeyManagerParameters implements ManagerFactoryParameters {
    private SpakeIdentity spakeIdentity;
    private byte[] clientPassword;
    private byte[] pakeContext;

    private SpakeClientKeyManagerParameters() {}

    /**
     * Builder for {@link SpakeClientKeyManagerParameters}.
     *
     * Before running {@link build}, the identity, password and context must be set through {@link
     * setIdentity}, {@link setClientPassword} and {@link setPakeContext} respectively.
     */
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static final class Builder {
        private SpakeIdentity spakeIdentity;
        private byte[] clientPassword;
        private byte[] pakeContext;

        public Builder() {}

        /**
         * Sets the client's identity using individual components.
         *
         * @param clientIdentity The client's identity.
         * @param serverIdentity The server's identity.
         * @return This builder.
         */
        @NonNull
        public Builder setIdentity(@NonNull byte[] clientIdentity, @NonNull byte[] serverIdentity) {
            return setIdentity(new SpakeIdentity(clientIdentity, serverIdentity));
        }

        /**
         * Sets the identity using a {@link SpakeIdentity} object.
         *
         * @param spakeIdentity The combined identity of the client and server.
         * @return This builder.
         */
        @NonNull
        public Builder setIdentity(@NonNull SpakeIdentity spakeIdentity) {
            requireNonNull(spakeIdentity, "The identity needs to be set");
            this.spakeIdentity = spakeIdentity;
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
            requireNonNull(password, "The password needs to be set");
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
            requireNonNull(context, "The context needs to be set");
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
            requireNonNull(spakeIdentity, "The identity needs to be set");
            requireNonNull(clientPassword, "The password needs to be set");
            requireNonNull(pakeContext, "The context needs to be set");

            SpakeClientKeyManagerParameters params = new SpakeClientKeyManagerParameters();

            params.spakeIdentity = spakeIdentity;
            params.clientPassword = clientPassword;
            params.pakeContext = pakeContext;

            return params;
        }
    }

    /**
     * Gets the combined identity of the client and server.
     *
     * @return The {@link SpakeIdentity}.
     */
    public @NonNull SpakeIdentity getSpakeIdentity() {
        return spakeIdentity;
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
