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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RunWith(JUnit4.class)
public class PakeServerKeyManagerParametersTest {
    private static final byte[] CLIENT_ID_1 = new byte[] {1, 2, 3};
    private static final byte[] SERVER_ID_1 = new byte[] {4, 5, 6};
    private static final byte[] CLIENT_ID_2 = new byte[] {7, 8, 9};
    private static final byte[] SERVER_ID_2 = new byte[] {10, 11, 12};
    private static final byte[] PASSWORD_BYTES = new byte[] {1, 2, 3};

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_valid() {
        PakeEndpoints endpoint1 = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeOption option1 = createOption("SPAKE2PLUS_PRERELEASE", "password");
        PakeEndpoints endpoint2 = new PakeEndpoints(CLIENT_ID_2, SERVER_ID_2);
        PakeOption option2 = createOption("SPAKE2PLUS_PRERELEASE", "w0", "registration_record");

        PakeServerKeyManagerParameters params = new PakeServerKeyManagerParameters.Builder()
                                                        .addEndpoint(endpoint1)
                                                        .addOption(endpoint1, option1)
                                                        .addEndpoint(endpoint2)
                                                        .addOption(endpoint2, option2)
                                                        .build();

        assertEquals(option1, params.getOptions(endpoint1).get(0));
        assertEquals(option2, params.getOptions(endpoint2).get(0));
    }

    @Test(expected = InvalidParameterException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_noEndpoints() {
        new PakeServerKeyManagerParameters.Builder().build();
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_nullEndpoint() {
        new PakeServerKeyManagerParameters.Builder().addEndpoint(null);
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_duplicateEndpoint() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeEndpoints sameEndpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint);
        assertThrows(InvalidParameterException.class, () -> builder.addEndpoint(sameEndpoint));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_nullOption() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint);
        assertThrows(NullPointerException.class, () -> builder.addOption(endpoint, null));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_duplicateOptionAlgorithm() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeOption options = createOption("SPAKE2PLUS_PRERELEASE", "password");
        PakeOption sameOptions = createOption("SPAKE2PLUS_PRERELEASE", "password");
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint).addOption(
                        endpoint, options);
        assertThrows(
                InvalidParameterException.class, () -> builder.addOption(endpoint, sameOptions));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_endpointWithNoOptions() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint);
        assertThrows(InvalidParameterException.class, () -> builder.build());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testGetOptions_nonExistingEndpoint() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeServerKeyManagerParameters params =
                new PakeServerKeyManagerParameters.Builder()
                        .addEndpoint(endpoint)
                        .addOption(endpoint, createOption("SPAKE2PLUS_PRERELEASE", "password"))
                        .build();
        PakeEndpoints nonExistingEndpoint = new PakeEndpoints(CLIENT_ID_2, SERVER_ID_2);
        assertThrows(InvalidParameterException.class, () -> params.getOptions(nonExistingEndpoint));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testHasEndpoint() {
        PakeEndpoints endpoint1 = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeEndpoints endpoint2 = new PakeEndpoints(CLIENT_ID_2, SERVER_ID_2);
        PakeServerKeyManagerParameters params =
                new PakeServerKeyManagerParameters.Builder()
                        .addEndpoint(endpoint1)
                        .addOption(endpoint1, createOption("SPAKE2PLUS_PRERELEASE", "password"))
                        .build();
        assert (params.hasEndpoint(endpoint1));
        assert (!params.hasEndpoint(endpoint2));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testGetEndpoints() {
        PakeEndpoints endpoint1 = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeOption option1 = createOption("SPAKE2PLUS_PRERELEASE", "password");
        PakeEndpoints endpoint2 = new PakeEndpoints(CLIENT_ID_2, SERVER_ID_2);
        PakeOption option2 = createOption("SPAKE2PLUS_PRERELEASE", "w0", "registration_record");

        PakeServerKeyManagerParameters params = new PakeServerKeyManagerParameters.Builder()
                                                        .addEndpoint(endpoint1)
                                                        .addOption(endpoint1, option1)
                                                        .addEndpoint(endpoint2)
                                                        .addOption(endpoint2, option2)
                                                        .build();
        Set<PakeEndpoints> expectedEndpoints = new HashSet<>();
        expectedEndpoints.add(endpoint1);
        expectedEndpoints.add(endpoint2);
        assertEquals(expectedEndpoints, params.getEndpoints());
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_spake2PlusPrerelease_w0WithoutRegistrationRecord() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeOption option = createOption("SPAKE2PLUS_PRERELEASE", "w0", "w1");
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint);
        assertThrows(InvalidParameterException.class, () -> builder.addOption(endpoint, option));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_spake2PlusPrerelease_w0WithRegistrationRecord() {
        PakeEndpoints endpoint = new PakeEndpoints(CLIENT_ID_1, SERVER_ID_1);
        PakeOption option = createOption("SPAKE2PLUS_PRERELEASE", "w0", "registration_record");
        PakeServerKeyManagerParameters.Builder builder =
                new PakeServerKeyManagerParameters.Builder().addEndpoint(endpoint).addOption(
                        endpoint, option);
        PakeServerKeyManagerParameters params = builder.build();
        assertEquals(option, params.getOptions(endpoint).get(0));
    }

    private static PakeOption createOption(String algorithm, String... keys) {
        PakeOption.Builder builder = new PakeOption.Builder(algorithm);
        for (String key : keys) {
            builder.addMessageComponent(key, PASSWORD_BYTES);
        }
        return builder.build();
    }
}
