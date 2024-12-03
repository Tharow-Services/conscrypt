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

import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidParameterException;

@RunWith(JUnit4.class)
public class SpakeServerKeyManagerParametersTest {
    private static final byte[] CLIENT_IDENTITY = "client".getBytes();
    private static final byte[] SERVER_IDENTITY = "server".getBytes();
    private static final byte[] PASSWORD = "password".getBytes();
    private static final byte[] PAKE_CONTEXT = "context".getBytes();

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(CLIENT_IDENTITY, SERVER_IDENTITY, PASSWORD)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();

        assertArrayEquals(PASSWORD, params.getPassword(CLIENT_IDENTITY, SERVER_IDENTITY));
        assertArrayEquals(PAKE_CONTEXT, params.getPakeContext());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilderWithSpakeIdentity() {
        SpakeServerKeyManagerParameters params =
                new SpakeServerKeyManagerParameters.Builder()
                        .addPasswordMapping(
                                new SpakeIdentity(CLIENT_IDENTITY, SERVER_IDENTITY), PASSWORD)
                        .setPakeContext(PAKE_CONTEXT)
                        .build();

        assertArrayEquals(PASSWORD, params.getPassword(CLIENT_IDENTITY, SERVER_IDENTITY));
        assertArrayEquals(PAKE_CONTEXT, params.getPakeContext());
    }

    @Test(expected = InvalidParameterException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNoPasswordMappings() {
        new SpakeServerKeyManagerParameters.Builder().setPakeContext(PAKE_CONTEXT).build();
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullContext() {
        new SpakeServerKeyManagerParameters.Builder()
                .addPasswordMapping(CLIENT_IDENTITY, SERVER_IDENTITY, PASSWORD)
                .build();
    }
}
