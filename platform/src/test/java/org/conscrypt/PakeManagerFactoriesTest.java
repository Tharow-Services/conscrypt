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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import android.net.ssl.PakeClientKeyManagerParameters;
import android.net.ssl.PakeEndpoints;
import android.net.ssl.PakeOption;
import javax.net.ssl.TrustManager;
import javax.net.ssl.KeyManager;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStoreException;
import java.security.InvalidAlgorithmParameterException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * @hide This class is not part of the Android public SDK API
 */
public class PakeManagerFactoriesTest {
    private static final byte[] CLIENT_ID = new byte[] {4, 5, 6};
    private static final byte[] SERVER_ID = new byte[] {7, 8, 9};
    private static final byte[] W_VALID =
            new byte[] {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            };
    private static final byte[] W_INVALID = new byte[] {1, 2};
    private static final byte[] REGISTRATION_RECORD =
            new byte[] {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
                44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
            };

    @Test
    public void testEngineInitParameters() throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        byte[] password = new byte[] {1, 2, 3};
        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("password", password)
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
        // Initialize with valid parameters
        keyManagerFactory.engineInit(params);
        // Try to initialize again
        assertThrows(IllegalStateException.class, () -> keyManagerFactory.engineInit(params));

        PakeTrustManagerFactory trustManagerFactory = new PakeTrustManagerFactory();
        // The trust manager factory does not accept parameters
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> trustManagerFactory.engineInit(params));
        trustManagerFactory.engineInit((ManagerFactoryParameters) null);
    }

    @Test
    public void testEngineGetKeyManagers() throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory factory = new PakeKeyManagerFactory();
        assertThrows(IllegalStateException.class, () -> factory.engineGetKeyManagers());

        byte[] password = new byte[] {1, 2, 3};
        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("password", password)
                        .build();

        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder()
                        .setClientId(CLIENT_ID.clone())
                        .setServerId(SERVER_ID.clone())
                        .addOption(option)
                        .build();

        factory.engineInit(params);
        KeyManager[] keyManagers = factory.engineGetKeyManagers();
        assertEquals(1, keyManagers.length);

        Spake2PlusKeyManager keyManager = (Spake2PlusKeyManager) keyManagers[0];
        assertArrayEquals(password, keyManager.getPassword());
        assertArrayEquals(new byte[] {4, 5, 6}, keyManager.getIdProver());
        assertArrayEquals(new byte[] {7, 8, 9}, keyManager.getIdVerifier());
    }

    @Test
    public void testParameters_w0w1Valid() throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("w0", W_VALID.clone())
                        .addMessageComponent("w1", W_VALID.clone())
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder().addOption(option).build();

        keyManagerFactory.engineInit(params);
    }

    @Test
    public void testParameters_w0w1Invalid() throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("w0", W_VALID.clone())
                        .addMessageComponent("w1", W_INVALID.clone())
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeClientKeyManagerParameters params =
                new PakeClientKeyManagerParameters.Builder().addOption(option).build();
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> keyManagerFactory.engineInit(params));
    }

    @Test
    public void testParameters_w0registrationRecordValid()
            throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("w0", W_VALID.clone())
                        .addMessageComponent("registrationRecord", REGISTRATION_RECORD.clone())
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeServerKeyManagerParameters params =
                new PakeServerKeyManagerParameters.Builder()
                        .addOption(Client_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();
        keyManagerFactory.engineInit(params);
    }

    @Test
    public void testParameters_w0registrationRecordInvalid()
            throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("w0", W_VALID.clone())
                        .addMessageComponent("registrationRecord", W_INVALID.clone())
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeServerKeyManagerParameters params =
                new PakeServerKeyManagerParameters.Builder()
                        .addOption(Client_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> keyManagerFactory.engineInit(params));
    }

    @Test
    public void testParameters_w0registrationRecordInvalid_2()
            throws InvalidAlgorithmParameterException {
        PakeKeyManagerFactory keyManagerFactory = new PakeKeyManagerFactory();

        PakeOption option =
                new PakeOption.Builder("SPAKE2PLUS_PRERELEASE")
                        .addMessageComponent("w0", W_INVALID.clone())
                        .addMessageComponent("registrationRecord", REGISTRATION_RECORD.clone())
                        .build();

        assertThrows(KeyStoreException.class, () -> keyManagerFactory.engineInit(null, null));

        PakeServerKeyManagerParameters params =
                new PakeServerKeyManagerParameters.Builder()
                        .addOption(Client_ID.clone(), SERVER_ID.clone(), Arrays.asList(option))
                        .build();

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> keyManagerFactory.engineInit(params));
    }

    @Test
    public void testEngineGetTrustManagers() {
        PakeTrustManagerFactory factory = new PakeTrustManagerFactory();
        TrustManager[] trustManagers = factory.engineGetTrustManagers();
        assertEquals(1, trustManagers.length);
        assertEquals(Spake2PlusTrustManager.class, trustManagers[0].getClass());
    }
}
