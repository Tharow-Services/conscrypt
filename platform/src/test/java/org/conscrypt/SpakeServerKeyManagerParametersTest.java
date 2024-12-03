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

package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;

@RunWith(JUnit4.class)
public class SpakeServerKeyManagerParametersTest {
    private static final byte[] CLIENT_ID_1 = "client1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLIENT_ID_2 = "client2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER_ID_1 = "server1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER_ID_2 = "server2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PASSWORD_1 = "password1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PASSWORD_2 = "password2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PAKE_CONTEXT = "pake_context".getBytes(StandardCharsets.UTF_8);

    @Test
    public void testBuild_noPasswordMappings() {
        assertThrows(InvalidParameterException.class,
                () -> new SpakeServerKeyManagerParameters.Builder().build());
    }

    @Test
    public void testBuild_onePasswordMapping() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertArrayEquals(PASSWORD_1, params.getPassword(CLIENT_ID_1, SERVER_ID_1));
    }

    @Test
    public void testBuild_multiplePasswordMappings() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .addPasswordMapping(CLIENT_ID_2, SERVER_ID_2, PASSWORD_2)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertArrayEquals(PASSWORD_1, params.getPassword(CLIENT_ID_1, SERVER_ID_1));
        assertArrayEquals(PASSWORD_2, params.getPassword(CLIENT_ID_2, SERVER_ID_2));
    }

    @Test
    public void testGetPassword_noMapping() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertNull(params.getPassword(CLIENT_ID_2, SERVER_ID_2));
    }

    @Test
    public void testGetPassword_incorrectClientIdentity() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertNull(params.getPassword(CLIENT_ID_2, SERVER_ID_1));
    }

    @Test
    public void testGetPassword_incorrectServerIdentity() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertNull(params.getPassword(CLIENT_ID_1, SERVER_ID_2));
    }

    @Test
    public void testSetGetPakeContext() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();
        assertArrayEquals(PAKE_CONTEXT, params.getPakeContext());
    }

    @Test
    public void testMissingPakeContext() {
        assertThrows(NullPointerException.class,
                ()
                        -> new SpakeServerKeyManagerParameters.Builder()
                                   .addPasswordMapping(CLIENT_ID_1, SERVER_ID_1, PASSWORD_1)
                                   .build());
    }
}
