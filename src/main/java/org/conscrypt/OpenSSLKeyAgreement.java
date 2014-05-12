/*
 * Copyright (C) 2014 The Android Open Source Project
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Key agreement backed by the OpenSSL engine.
 */
public final class OpenSSLKeyAgreement extends KeyAgreementSpi {

    /** OpenSSL handle of the private key. Only available after the engine has been initialized. */
    private OpenSSLKey mOpenSslPrivateKey;

    /** Agreed key. Only available after {@link #engineDoPhase(Key, boolean)} completes. */
    private byte[] mResult;

    @Override
    public Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (mOpenSslPrivateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (!lastPhase) {
            throw new IllegalStateException("Only one phase is supported");
        }

        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if (!(key instanceof PublicKey)) {
            throw new InvalidKeyException("Not a public key: " + key.getClass());
        }
        OpenSSLKey peerKey = translateKeyToOpenSSLKey(key);

        byte[] skey = NativeCrypto.EVP_PKEY_derive(mOpenSslPrivateKey.getPkeyContext(),
                peerKey.getPkeyContext());
        mResult = skey;

        return null; // No intermediate key
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws ShortBufferException {
        checkCompleted();
        int available = sharedSecret.length - offset;
        if (mResult.length > available) {
            throw new ShortBufferException(
                    "Needed: " + mResult.length + ", available: " + available);
        }

        System.arraycopy(mResult, 0, sharedSecret, offset, mResult.length);
        return mResult.length;
    }

    @Override
    protected byte[] engineGenerateSecret() {
        checkCompleted();
        return mResult;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) {
        checkCompleted();
        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }
        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("Not a private key: " + key.getClass());
        }

        mOpenSslPrivateKey = translateKeyToOpenSSLKey(key);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
        }
        engineInit(key, random);
    }

    private void checkCompleted() {
        if (mResult == null) {
            throw new IllegalStateException("Key agreement not completed");
        }
    }

    private static OpenSSLKey translateKeyToOpenSSLKey(Key key) throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(),
                    OpenSSLProvider.PROVIDER_NAME);
            return ((OpenSSLKeyHolder) kf.translateKey(key)).getOpenSSLKey();
        } catch (Exception e) {
            throw new InvalidKeyException("Could not convert to OpenSSLProvider format", e);
        }
    }
}
