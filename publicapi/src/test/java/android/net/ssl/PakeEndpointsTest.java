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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidParameterException;

@RunWith(JUnit4.class)
public class PakeEndpointsTest {
    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testDirect() {
        PakeEndpoints endpoints = PakeEndpoints.DIRECT;
        assertNull(endpoints.getClientId());
        assertNull(endpoints.getServerId());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testConstructor() {
        byte[] clientId = new byte[] {1, 2, 3};
        byte[] serverId = new byte[] {4, 5, 6};
        PakeEndpoints endpoints = new PakeEndpoints(clientId, serverId);
        assertArrayEquals(clientId, endpoints.getClientId());
        assertArrayEquals(serverId, endpoints.getServerId());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testEquals() {
        byte[] clientId = new byte[] {1, 2, 3};
        byte[] serverId = new byte[] {4, 5, 6};
        PakeEndpoints endpoints1 = new PakeEndpoints(clientId, serverId);
        PakeEndpoints endpoints2 = new PakeEndpoints(clientId, serverId);
        PakeEndpoints endpoints3 = new PakeEndpoints(new byte[] {7, 8, 9}, serverId);
        PakeEndpoints endpoints4 = new PakeEndpoints(clientId, new byte[] {10, 11, 12});

        assertEquals(endpoints1, endpoints2);
        assertNotEquals(endpoints1, endpoints3);
        assertNotEquals(endpoints1, endpoints4);
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testHashCode() {
        byte[] clientId = new byte[] {1, 2, 3};
        byte[] serverId = new byte[] {4, 5, 6};
        PakeEndpoints endpoints1 = new PakeEndpoints(clientId, serverId);
        PakeEndpoints endpoints2 = new PakeEndpoints(clientId, serverId);

        assertEquals(endpoints1.hashCode(), endpoints2.hashCode());
    }
}
