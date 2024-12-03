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

import static java.util.Objects.requireNonNull;

import android.net.ssl.SpakeClientKeyManagerParameters;
import android.net.ssl.SpakeServerKeyManagerParameters;

import com.android.org.conscrypt.io.IoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

/**
 * SpakeKeyManagerFactory implementation.
 * @see KeyManagerFactorySpi
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class SpakeKeyManagerFactory extends KeyManagerFactorySpi {
    SpakeServerKeyManagerParameters serverParams;
    SpakeClientKeyManagerParameters clientParams;

    /**
     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
     */
    @Override
    protected void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new KeyStoreException("KeyStore not supported");
    }

    /**
     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
     */
    @Override
    protected void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        requireNonNull(spec);
        if (spec instanceof SpakeServerKeyManagerParameters) {
            serverParams = (SpakeServerKeyManagerParameters) spec;
        } else if (spec instanceof SpakeClientKeyManagerParameters) {
            clientParams = (SpakeClientKeyManagerParameters) spec;
        } else {
            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
        }
    }

    /**
     * @see KeyManagerFactorySpi#engineGetKeyManagers()
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (serverParams != null) {
            // TODO: Add SpakeServerKeyManager
            // return new KeyManager[] { new SpakeServerKeyManager(serverParams) };
            return null;
        } else if (clientParams != null) {
            // TODO: Add SpakeClientKeyManager
            // return new KeyManager[] { new SpakeClientKeyManager(clientParams) };
            return null;
        } else {
            throw new IllegalStateException("SpakeKeyManagerFactory is not initialized");
        }
    }
}
