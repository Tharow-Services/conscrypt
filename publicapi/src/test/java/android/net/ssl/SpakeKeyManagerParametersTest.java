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

import android.net.ssl.SpakeKeyManagerParameters.Prover;
import android.net.ssl.SpakeKeyManagerParameters.Prover.Builder;
import android.net.ssl.SpakeKeyManagerParameters.Verifier;
import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidParameterException;

@RunWith(JUnit4.class)
public class SpakeKeyManagerParametersTest {
    private static final byte[] PASSWORD = "test_password".getBytes();
    private static final byte[] ID_PROVER = "prover_id".getBytes();
    private static final byte[] ID_VERIFIER = "verifier_id".getBytes();
    private static final byte[] CONTEXT = "test_context".getBytes();

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testProverBuilder() {
        SpakeKeyManagerParameters prover = new Prover.Builder(PASSWORD)
                                                   .setIdProver(ID_PROVER)
                                                   .setIdVerifier(ID_VERIFIER)
                                                   .setContext(CONTEXT)
                                                   .build();

        assertArrayEquals(PASSWORD, prover.getPassword());
        assertArrayEquals(ID_PROVER, prover.getIdProver());
        assertArrayEquals(ID_VERIFIER, prover.getIdVerifier());
        assertArrayEquals(CONTEXT, prover.getContext());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testVerifierBuilder() {
        SpakeKeyManagerParameters verifier = new Verifier.Builder(PASSWORD)
                                                     .setIdProver(ID_PROVER)
                                                     .setIdVerifier(ID_VERIFIER)
                                                     .setContext(CONTEXT)
                                                     .build();

        assertArrayEquals(PASSWORD, verifier.getPassword());
        assertArrayEquals(ID_PROVER, verifier.getIdProver());
        assertArrayEquals(ID_VERIFIER, verifier.getIdVerifier());
        assertArrayEquals(CONTEXT, verifier.getContext());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testEmptyPassword() {
        assertThrows(InvalidParameterException.class, () -> new Prover.Builder(new byte[0]));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullPassword() {
        assertThrows(NullPointerException.class, () -> new Prover.Builder(null));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullIdProver() {
        assertThrows(
                NullPointerException.class, () -> new Prover.Builder(PASSWORD).setIdProver(null));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullIdVerifier() {
        assertThrows(
                NullPointerException.class, () -> new Prover.Builder(PASSWORD).setIdVerifier(null));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testNullContext() {
        assertThrows(
                NullPointerException.class, () -> new Prover.Builder(PASSWORD).setContext(null));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testEmptyParameters() {
        SpakeKeyManagerParameters verifier = new Verifier.Builder(PASSWORD)
                                                     .setIdProver(SpakeKeyManagerParameters.UNSET)
                                                     .setIdVerifier(SpakeKeyManagerParameters.UNSET)
                                                     .setContext(SpakeKeyManagerParameters.UNSET)
                                                     .build();

        assertArrayEquals(PASSWORD, verifier.getPassword());
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, verifier.getIdProver());
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, verifier.getIdVerifier());
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, verifier.getContext());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testUnsetParameters() {
        SpakeKeyManagerParameters prover = new Prover.Builder(PASSWORD).build();
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, prover.getIdProver());
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, prover.getIdVerifier());
        assertArrayEquals(SpakeKeyManagerParameters.UNSET, prover.getContext());
    }
}
