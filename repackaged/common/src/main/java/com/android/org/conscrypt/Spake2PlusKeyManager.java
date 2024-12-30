/* GENERATED SOURCE. DO NOT MODIFY. */
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

import android.net.ssl.PakeOption;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.KeyManager;
import java.security.Principal;

/**
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class Spake2PlusKeyManager implements KeyManager {
  private final List<PakeOption> options;
  private final byte[] idClient;
  private final byte[] idServer;
  private final boolean isClient;

  Spake2PlusKeyManager(List<PakeOption> options,
      byte[] idClient, byte[] idServer, boolean isClient) {
    this.options = options;
    this.idClient = idClient;
    this.idServer = idServer;
    this.isClient = isClient;
  }

  public String chooseEngineAlias(String keyType,
          Principal[] issuers, SSLEngine engine) {
    throw new UnsupportedOperationException("Not implemented");
  }

  public String chooseEngineClientAlias(String[] keyType,
          Principal[] issuers, SSLEngine engine) {
    throw new UnsupportedOperationException("Not implemented");
  }

  public byte[] getOptions() {
    return options;
  }

  public byte[] getIdProver() {
    return idClient;
  }

  public byte[] getIdVerifier() {
    return idServer;
  }

  public boolean isClient() {
    return isClient;
  }
}