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
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.charset.StandardCharsets;

@RunWith(JUnit4.class)
public class SpakeClientKeyManagerParametersTest {
    private static final byte[] CLIENT_ID = "client".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER_ID = "server".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PASSWORD = "password".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PAKE_CONTEXT = "pake_context".getBytes(StandardCharsets.UTF_8);

    @Test
    public void testBuild_allParametersSet() {
        SpakeClientKeyManagerParameters params = new SpakeClientKeyManagerParameters.Builder()
                                                         .setClientIdentity(CLIENT_ID)
                                                         .setServerIdentity(SERVER_ID)
                                                         .setClientPassword(PASSWORD)
                                                         .setPakeContext(PAKE_CONTEXT)
                                                         .build();
        assertArrayEquals(CLIENT_ID, params.getClientIdentity());
        assertArrayEquals(SERVER_ID, params.getServerIdentity());
        assertArrayEquals(PASSWORD, params.getClientPassword());
        assertArrayEquals(PAKE_CONTEXT, params.getPakeContext());
    }

    @Test
    public void testBuild_missingClientIdentity() {
        assertThrows(NullPointerException.class,
                ()
                        -> new SpakeClientKeyManagerParameters.Builder()
                                   .setServerIdentity(SERVER_ID)
                                   .setClientPassword(PASSWORD)
                                   .setPakeContext(PAKE_CONTEXT)
                                   .build());
    }

    @Test
    public void testBuild_missingServerIdentity() {
        assertThrows(NullPointerException.class,
                ()
                        -> new SpakeClientKeyManagerParameters.Builder()
                                   .setClientIdentity(CLIENT_ID)
                                   .setClientPassword(PASSWORD)
                                   .setPakeContext(PAKE_CONTEXT)
                                   .build());
    }

    @Test
    public void testBuild_missingClientPassword() {
        assertThrows(NullPointerException.class,
                ()
                        -> new SpakeClientKeyManagerParameters.Builder()
                                   .setClientIdentity(CLIENT_ID)
                                   .setServerIdentity(SERVER_ID)
                                   .setPakeContext(PAKE_CONTEXT)
                                   .build());
    }

    @Test
    public void testBuild_missingPakeContext() {
        assertThrows(NullPointerException.class,
                ()
                        -> new SpakeClientKeyManagerParameters.Builder()
                                   .setClientIdentity(CLIENT_ID)
                                   .setServerIdentity(SERVER_ID)
                                   .setClientPassword(PASSWORD)
                                   .build());
    }
}