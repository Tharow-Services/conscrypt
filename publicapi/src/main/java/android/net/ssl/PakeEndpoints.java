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

import android.annotation.FlaggedApi;
import android.annotation.SystemApi;

import libcore.util.NonNull;
import libcore.util.Nullable;

import java.security.InvalidParameterException;
import java.util.Arrays;

import javax.net.ssl.ManagerFactoryParameters;

/**
 * An immutable class representing the endpoints involved in a PAKE (Password
 * Authenticated Key Exchange) exchange.
 *
 * <p>This class holds the identifiers for the client and server participating in
 * the PAKE exchange. These identifiers are used to derive the unique
 * cryptographic keys for the connection.</p>
 *
 * <p>Instances of this class are immutable.</p>
 *
 * @hide
 */
@SystemApi
@FlaggedApi(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
public final class PakeEndpoints {
    /**
     * A constant representing a direct connection with no specific endpoints.
     */
    public static final PakeEndpoints DIRECT = new PakeEndpoints(null, null);

    /**
     * The identifier for the client.
     */
    private final byte[] clientId;

    /**
     * The identifier for the server.
     */
    private final byte[] serverId;

    /**
     * Cached hash code.
     */
    private final int hashCode;

    /**
     * Constructor for creating {@link PakeEndpoints} instances.
     *
     * @param clientId The identifier for the client. May be null.
     * @param serverId The identifier for the server. May be null.
     */
    public PakeEndpoints(@Nullable byte[] clientId, @Nullable byte[] serverId) {
        this.clientId = clientId;
        this.serverId = serverId;
        this.hashCode = computeHashCode();
    }

    /**
     * Returns the identifier for the client.
     *
     * @return The identifier for the client.
     */
    public @Nullable byte[] getClientId() {
        return clientId;
    }

    /**
     * Returns the identifier for the server.
     *
     * @return The identifier for the server.
     */
    public @Nullable byte[] getServerId() {
        return serverId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        PakeEndpoints that = (PakeEndpoints) o;
        return Arrays.equals(clientId, that.clientId) && Arrays.equals(serverId, that.serverId);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    private int computeHashCode() {
        int result = Arrays.hashCode(clientId);
        result = 31 * result + Arrays.hashCode(serverId);
        return result;
    }
}
