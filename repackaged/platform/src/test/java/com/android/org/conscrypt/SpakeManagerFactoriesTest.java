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

package com.android.org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import android.net.ssl.SpakeKeyManagerParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.KeyManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class SpakeManagerFactoriesTest {

  @Test
  public void testEngineInitParameters() {
    SpakeKeyManagerFactory keyManagerFactory = new SpakeKeyManagerFactory();

    assertThrows(KeyStoreException.class, () -> factory.engineInit(null, null));

    SpakeKeyManagerParameters params = new SpakeKeyManagerParameters.Builder().build();
    // Initialize with valid parameters
    keyManagerFactory.engineInit(params);
    // Try to initialize again
    assertThrows(IllegalStateException.class,
        () -> keyManagerFactory.engineInit(params));

    SpakeTrustManagerFactory trustManagerFactory = new SpakeTrustManagerFactory();
    // The trust manager factory does not accept parameters
    assertThrows(InvalidAlgorithmParameterException.class, () -> trustManagerFactory.engineInit(params));
    trustManagerFactory.engineInit((ManagerFactoryParameters) null);
  }

  @Test
  public void testEngineGetKeyManagers() {
    SpakeKeyManagerFactory factory = new SpakeKeyManagerFactory();
    assertThrows(IllegalStateException.class, () -> factory.engineGetKeyManagers());

    byte[] password = "password".getBytes();
    byte[] idProver = "id_prover".getBytes();
    byte[] idVerifier = "id_verifier".getBytes();
    byte[] context = "context".getBytes();

    SpakeKeyManagerParameters params = new SpakeKeyManagerParameters.Builder()
        .setClientPassword(password)
        .setIdProver(idProver)
        .setIdVerifier(idVerifier)
        .setContext(context)
        .build();

    factory.engineInit(params);
    KeyManager[] keyManagers = factory.engineGetKeyManagers();
    assertEquals(1, keyManagers.length);

    SpakeKeyManager keyManager = (SpakeKeyManager) keyManagers[0];
    assertArrayEquals(password, keyManager.getPassword());
    assertArrayEquals(idProver, keyManager.getIdProver());
    assertArrayEquals(idVerifier, keyManager.getIdVerifier());
    assertArrayEquals(context, keyManager.getContext());
  }

  @Test
  public void testEngineGetTrustManagers() {
    SpakeTrustManagerFactory factory = new SpakeTrustManagerFactory();
    TrustManager[] trustManagers = factory.engineGetTrustManagers();
    assertEquals(1, trustManagers.length);
    assertEquals(SpakeTrustManager.class, trustManagers[0].getClass());
  }
}