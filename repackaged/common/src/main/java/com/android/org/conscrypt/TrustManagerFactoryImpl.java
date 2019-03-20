/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2016 The Android Open Source Project
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

// License from Apache Harmony:
/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.android.org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 *
 * TrustManagerFactory service provider interface implementation.
 *
 * @see javax.net.ssl.TrustManagerFactorySpi
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class TrustManagerFactoryImpl extends TrustManagerFactorySpi {

    private KeyStore keyStore;

    /**
     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(KeyStore)
     */
    @Override
    public void engineInit(KeyStore ks) throws KeyStoreException {
        if (ks != null) {
            keyStore = ks;
        } else {
            keyStore = Platform.getDefaultCertKeyStore();
        }
    }

    /**
     * @see javax.net.ssl#engineInit(ManagerFactoryParameters)
     */
    @Override
    public void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "ManagerFactoryParameters not supported");
    }

    /**
     * @see javax.net.ssl#engineGetTrustManagers()
     */
    @Override
    public TrustManager[] engineGetTrustManagers() {
        if (keyStore == null) {
            throw new IllegalStateException(
                    "TrustManagerFactory is not initialized");
        }
        return new TrustManager[] { new TrustManagerImpl(keyStore) };
    }
}
