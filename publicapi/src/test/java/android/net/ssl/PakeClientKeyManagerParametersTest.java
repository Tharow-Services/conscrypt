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
import static org.junit.Assert.assertNull;

import android.platform.test.annotations.RequiresFlagsEnabled;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.InvalidParameterException;
import java.util.List;

@RunWith(JUnit4.class)
public class PakeClientKeyManagerParametersTest {
    private static final byte[] PASSWORD = new byte[] {1, 2, 3};

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_valid() {
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD.clone())
                                    .build();
        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
        assertNull(params.getClientId());
        assertNull(params.getServerId());
        assertEquals(1, params.getOptions().size());
        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_withEndpoints() {
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD.clone())
                                    .build();
        PakeEndpoints endpoints = new PakeEndpoints(new byte[] {4, 5, 6}, new byte[] {7, 8, 9});
        PakeClientKeyManagerParameters params = new PakeClientKeyManagerParameters.Builder()
                                                        .setEndpoints(endpoints)
                                                        .addOption(option)
                                                        .build();
        assertEquals(endpoints.getIdClient(), params.getClientId());
        assertEquals(endpoints.getIdServer(), params.getServerId());
        assertEquals(1, params.getOptions().size());
        assertArrayEquals(PASSWORD, params.getOptions().get(0).getMessageComponent("password"));
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_nullEndpoints() {
        new PakeClientKeyManagerParameters.Builder().setEndpoints(null);
    }

    @Test(expected = InvalidParameterException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_noOptions() {
        new PakeClientKeyManagerParameters.Builder().build();
    }

    @Test(expected = NullPointerException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_nullOption() {
        new PakeClientKeyManagerParameters.Builder().addOption(null);
    }

    @Test(expected = InvalidParameterException.class)
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testBuilder_duplicateOptionNames() {
        PakeOption option1 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("password", PASSWORD.clone())
                                     .build();
        PakeOption option2 = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                     .addMessageComponent("w0", new byte[] {4, 5, 6})
                                     .addMessageComponent("w1", new byte[] {7, 8, 9})
                                     .build();
        new PakeClientKeyManagerParameters.Builder().addOption(option1).addOption(option2).build();
    }

    @Test
    @RequiresFlagsEnabled(com.android.org.conscrypt.flags.Flags.FLAG_SPAKE2PLUS_API)
    public void testGetOptions_returnsClone() {
        PakeOption option = new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                                    .addMessageComponent("password", PASSWORD.clone())
                                    .build();
        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
        List<PakeOption> options = params.getOptions();
        options.clear(); // Try to modify the returned list
        assertEquals(1, params.getOptions().size()); // The original list should be unchanged
    }
}
