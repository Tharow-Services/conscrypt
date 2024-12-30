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
import libcore.util.Nullable;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * Parameters for configuring a {@code KeyManager} that supports PAKE
 * (Password Authenticated Key Exchange) on the server side.
 *
 * <p>This class holds the necessary information for the {@code KeyManager} to
 * perform PAKE authentication, including a mapping of endpoints to their
 * corresponding PAKE options.</p>
 *
 * <p>Instances of this class are immutable. Use the {@link Builder} to create
 * instances.</p>
 *
 * @hide
 */
@SystemApi
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public final class PakeServerKeyManagerParameters implements ManagerFactoryParameters {
    /**
     * A map of endpoints to their corresponding PAKE options.
     */
    private final Map<PakeEndpoints, List<PakeOption>> endpoints;

    /**
     * Private constructor to enforce immutability.
     *
     * @param endpoints A map of endpoints to their corresponding PAKE options.
     */
    private PakeServerKeyManagerParameters(Map<PakeEndpoints, List<PakeOption>> endpoints) {
        this.endpoints = Collections.unmodifiableMap(new HashMap<>(endpoints));
    }

    /**
     * Returns an unmodifiable list of PAKE options for the given endpoint.
     *
     * @param endpoint The endpoint for which to retrieve the options.
     * @return An unmodifiable list of PAKE options for the given endpoint.
     */
    public @NonNull List<PakeOption> getOptions(@NonNull PakeEndpoints endpoint) {
        requireNonNull(endpoint, "Endpoint cannot be null.");
        List<PakeOption> options = endpoints.get(endpoint);
        if (options == null) {
            throw new InvalidParameterException("Endpoint not found.");
        }
        return Collections.unmodifiableList(options);
    }

    /**
     * Checks if the given endpoint exists in the parameters.
     *
     * @param endpoint The endpoint to check.
     * @return {@code true} if the endpoint exists, {@code false} otherwise.
     */
    public boolean hasEndpoint(@NonNull PakeEndpoints endpoint) {
        requireNonNull(endpoint, "Endpoint cannot be null.");
        return endpoints.containsKey(endpoint);
    }

    /**
     * A builder for creating {@link PakeServerKeyManagerParameters} instances.
     *
     * @hide
     */
    @SystemApi
    @FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public static final class Builder {
        private final Map<PakeEndpoints, List<PakeOption>> endpoints = new HashMap<>();

        /**
         * Adds an endpoint for PAKE authentication.
         *
         * @param endpoint The endpoint to add.
         * @return This builder.
         * @throws InvalidParameterException If the provided endpoint is null or already exists.
         */
        public @NonNull Builder addEndpoint(@NonNull PakeEndpoints endpoint) {
            requireNonNull(endpoint, "Endpoint cannot be null.");
            if (endpoints.containsKey(endpoint)) {
                throw new InvalidParameterException("Endpoint already exists in the map.");
            }
            endpoints.put(endpoint, new ArrayList<>());
            return this;
        }

        /**
         * Adds a PAKE option for the given endpoint.
         *
         * @param endpoint The endpoint for which to add the option.
         * @param option   The PAKE option to add.
         * @return This builder.
         * @throws InvalidParameterException If the provided endpoint or option is invalid.
         */
        public @NonNull Builder addOption(
                @NonNull PakeEndpoints endpoint, @NonNull PakeOption option) {
            requireNonNull(endpoint, "Endpoint cannot be null.");
            requireNonNull(option, "Option cannot be null.");

            if (!endpoints.containsKey(endpoint)) {
                throw new InvalidParameterException("Endpoint does not exist in the map.");
            }

            List<PakeOption> options = endpoints.get(endpoint);
            for (PakeOption existingOption : options) {
                if (existingOption.getName().equals(option.getName())) {
                    throw new InvalidParameterException(
                            "An option with the same name already exists.");
                }
            }

            options.add(option);
            return this;
        }

        /**
         * Builds a new {@link PakeServerKeyManagerParameters} instance.
         *
         * @return A new {@link PakeServerKeyManagerParameters} instance.
         * @throws InvalidParameterException If no endpoints are provided.
         */
        public @NonNull PakeServerKeyManagerParameters build() {
            if (endpoints.isEmpty()) {
                throw new InvalidParameterException("At least one endpoint must be provided.");
            }
            for (List<PakeOption> options : endpoints.values()) {
                if (options.isEmpty()) {
                    throw new InvalidParameterException(
                            "Each endpoint must have at least one option.");
                }
            }
            return new PakeServerKeyManagerParameters(endpoints);
        }
    }
}
