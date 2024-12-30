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

import static java.util.Objects.requireNonNull;

import android.net.ssl.PakeClientKeyManagerParameters;
import android.net.ssl.PakeServerKeyManagerParameters;

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
 * PakeKeyManagerFactory implementation.
 * @see KeyManagerFactorySpi
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public class PakeKeyManagerFactory extends KeyManagerFactorySpi {
    PakeClientKeyManagerParameters clientParams;
    PakeServerKeyManagerParameters serverParams;

    /**
     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
     */
    @Override
    public void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new KeyStoreException("KeyStore not supported");
    }

    /**
     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
     */
    @Override
    public void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        if (clientParams != null || serverParams != null) {
            throw new IllegalStateException("SpakeKeyManagerFactory is already initialized");
        }
        requireNonNull(spec);
        if (spec instanceof PakeClientKeyManagerParameters) {
            clientParams = (PakeClientKeyManagerParameters) spec;
        } else if (spec instanceof PakeServerKeyManagerParameters) {
            serverParams = (PakeServerKeyManagerParameters) spec;
        } else {
            throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
        }
    }

    /**
     * @see KeyManagerFactorySpi#engineGetKeyManagers()
     */
    @Override
    public KeyManager[] engineGetKeyManagers() {
        if (clientParams != null) {
            return new KeyManager[] { new Spake2PlusKeyManager(params.getOptions(),
                params.getIdClient(), params.getIdServer(), true) };
        } else if (serverParams != null) {
            return new KeyManager[] { new Spake2PlusKeyManager(params.getOptions(),
                params.getIdClient(), params.getIdServer(), false) };
        } else {
            throw new IllegalStateException("SpakeKeyManagerFactory is not initialized");
        }
    }
}
