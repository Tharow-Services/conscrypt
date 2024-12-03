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

import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SpakeIdentityTest {
    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testCombineIdentities() {
        byte[] clientIdentity = "client".getBytes();
        byte[] serverIdentity = "server".getBytes();
        byte[] expectedCombined = "clientserver".getBytes();

        SpakeIdentity spakeIdentity = new SpakeIdentity(clientIdentity, serverIdentity);
        assertArrayEquals(clientIdentity, spakeIdentity.getClientIdentity());
        assertArrayEquals(serverIdentity, spakeIdentity.getServerIdentity());
        // assertEquals(expectedCombined, spakeIdentity.combineIdentities());
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullClientIdentity() {
        new SpakeIdentity(null, "server".getBytes());
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullServerIdentity() {
        new SpakeIdentity("client".getBytes(), null);
    }
}
