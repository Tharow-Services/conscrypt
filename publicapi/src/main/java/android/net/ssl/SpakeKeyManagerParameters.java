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
import android.annotation.SystemApi;

import libcore.util.NonNull;

import java.security.InvalidParameterException;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * This class is used to provide specific data to a SPAKE2+ {@link
 * javax.net.ssl.KeyManagerFactory}.
 *
 * It has 2 possible concrete instances:
 *  - {@link Prover} - created through {@link Prover.Builder}
 *  - {@link Verifier} - created through {@link Verifier.Builder}
 *
 * @hide
 */
@SystemApi
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public class SpakeKeyManagerParameters implements ManagerFactoryParameters {
    /**
     * Use this to unset a certain parameter. Cannot be used for password.
     */
    public static final byte[] UNSET = new byte[0];

    private byte[] password;
    private byte[] idProver;
    private byte[] idVerifier;
    private byte[] context;

    private SpakeKeyManagerParameters() {}

    /**
     * Gets the shared password.
     *
     * @return the shared password.
     */
    public @NonNull byte[] getPassword() {
        return password;
    }

    /**
     * Gets the prover's ID.
     *
     * @return the ID. May be empty.
     */
    public @NonNull byte[] getIdProver() {
        return idProver;
    }

    /**
     * Gets the verifier's ID.
     *
     * @return the ID. May be empty.
     */
    public @NonNull byte[] getIdVerifier() {
        return idVerifier;
    }

    /**
     * Gets the SPAKE2+ context.
     *
     * @return the SPAKE2+ context. May be empty
     */
    public @NonNull byte[] getContext() {
        return context;
    }

    /**
     * Builder for {@link SpakeKeyManagerParameters}.
     *
     * @hide
     */
    @SystemApi
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static abstract class Builder {
        private byte[] password;
        private byte[] idProver = UNSET;
        private byte[] idVerifier = UNSET;
        private byte[] context = UNSET;

        /**
         * Constructor.
         *
         * @param password The shared password. Must not be empty.
         */
        protected Builder(@NonNull byte[] password) {
            requireNonNull(password, "The password needs to be set");
            if (password.length == 0) {
                throw new InvalidParameterException("The password must not be empty");
            }
            this.password = password;
        }

        /**
         * Sets the prover's identity using individual components.
         *
         * @param idProver The identity of the prover (client).
         * @return this builder.
         */
        @NonNull
        public Builder setIdProver(@NonNull byte[] idProver) {
            requireNonNull(idProver, "The idProver needs to be set");
            this.idProver = idProver;
            return this;
        }

        /**
         * Sets the verifier's identity using individual components.
         *
         * @param idVerifier The identity of the verifier (server).
         * @return this builder.
         */
        @NonNull
        public Builder setIdVerifier(@NonNull byte[] idVerifier) {
            requireNonNull(idVerifier, "The idVerifier needs to be set");
            this.idVerifier = idVerifier;
            return this;
        }

        /**
         * Sets the PAKE context.
         *
         * @param context The PAKE context.
         * @return this builder.
         */
        @NonNull
        public Builder setContext(@NonNull byte[] context) {
            requireNonNull(context, "The context needs to be set");
            this.context = context;
            return this;
        }

        /**
         * Builds the {@link SpakeKeyManagerParameters}.
         *
         * @return the built parameters.
         */
        @NonNull public abstract SpakeKeyManagerParameters build();

        @NonNull
        protected SpakeKeyManagerParameters doBuild(SpakeKeyManagerParameters params) {
            params.password = password;
            params.idProver = idProver;
            params.idVerifier = idVerifier;
            params.context = context;

            return params;
        }
    }

    /**
     * SPAKE2+ KeyManager parameters class for a Prover.
     *
     * @hide
     */
    @SystemApi
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static final class Prover extends SpakeKeyManagerParameters {
        private Prover() {}

        /**
         * Builder for the Prover.
         *
         * @hide
         */
        @SystemApi
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        public static final class Builder extends SpakeKeyManagerParameters.Builder {
            /**
             * Constructor.
             *
             * @param password The shared password. Must not be empty.
             */
            public Builder(@NonNull byte[] password) {
                super(password);
            }

            /**
             * Builds the {@link SpakeKeyManagerParameters}.
             *
             * @return the built parameters.
             */
            @Override
            @NonNull
            public SpakeKeyManagerParameters.Prover build() {
                Prover params = new Prover();
                return (Prover) doBuild(params);
            }
        }
    }

    /**
     * SPAKE2+ KeyManager parameters class for a Verifier.
     *
     * @hide
     */
    @SystemApi
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static final class Verifier extends SpakeKeyManagerParameters {
        private Verifier() {}

        /**
         *
         * Builder for the Verifier.
         *
         * @hide
         */
        @SystemApi
        @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
        public static final class Builder extends SpakeKeyManagerParameters.Builder {
            /**
             * Constructor.
             *
             * @param password The shared password. Must not be empty.
             */
            public Builder(@NonNull byte[] password) {
                super(password);
            }

            /**
             * Builds the {@link SpakeKeyManagerParameters}.
             *
             * @return the built parameters.
             */
            @Override
            @NonNull
            public SpakeKeyManagerParameters.Verifier build() {
                Verifier params = new Verifier();
                return (Verifier) doBuild(params);
            }
        }
    }
}
