/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.org.conscrypt.java.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

// Similar to KeyFactoryTestRSA, but uses custom RSA PublicKey
// implementation to exercise less common parts of RSAKeyFactory
/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class KeyFactoryTestCustomRSA
        extends AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {
    // BEGIN Android-Added: Allow access to deprecated BC algorithms.
    // Allow access to deprecated BC algorithms in this test, so we can ensure they
    // continue to work
    @ClassRule
    public static TestRule enableDeprecatedBCAlgorithmsRule =
            EnableDeprecatedBouncyCastleAlgorithmsRule.getInstance();
    // END Android-Added: Allow access to deprecated BC algorithms.

    public KeyFactoryTestCustomRSA() {
        super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new CipherAsymmetricCryptHelper("RSA").test(keyPair);
    }

    @Override
    public ServiceTester customizeTester(ServiceTester tester) {
        // BouncyCastle's KeyFactory.engineGetKeySpec() doesn't handle custom PublicKey
        // implmenetations.
        return tester.skipProvider("BC");
    }

    @Override
    protected PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new MyRSAPublicKey(DefaultKeys.getPublicKey("RSA"));
    }

    @Override
    protected PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new MyRSAPrivateKey(DefaultKeys.getPrivateKey("RSA"));
    }

    @Test
    public void testExtraBufferSpace_Private() throws Exception {
        PrivateKey privateKey = new MyRSAPrivateKey(DefaultKeys.getPrivateKey("RSA"));
        byte[] encoded = privateKey.getEncoded();
        byte[] longBuffer = new byte[encoded.length + 147];
        System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
        KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(longBuffer));
    }

    @Test
    public void testExtraBufferSpace_Public() throws Exception {
        PublicKey publicKey = new MyRSAPublicKey(DefaultKeys.getPublicKey("RSA"));
        byte[] encoded = publicKey.getEncoded();
        byte[] longBuffer = new byte[encoded.length + 147];
        System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(longBuffer));
    }

    @Test
    public void testInvalidKeySpec() throws Exception {
        Provider p = Security.getProvider(StandardNames.JSSE_PROVIDER_NAME);
        final KeyFactory factory = KeyFactory.getInstance("RSA", p);

        try {
            factory.getKeySpec(new MyRSAPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                    RSAPrivateKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new MyRSAPrivateKey(DefaultKeys.getPrivateKey("RSA"), "Invalid"),
                    RSAPrivateCrtKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }

        try {
            factory.getKeySpec(new MyRSAPublicKey(DefaultKeys.getPublicKey("RSA"), "Invalid"),
                    RSAPublicKeySpec.class);
            fail();
        } catch (InvalidKeySpecException e) {
            // expected
        }
    }

    class MyRSAPublicKey implements PublicKey {
        private PublicKey key;
        private String format;

        MyRSAPublicKey(PublicKey key) {
            this(key, key.getFormat());
        }

        MyRSAPublicKey(PublicKey key, String format) {
            assertEquals(key.getAlgorithm(), "RSA");
            this.key = key;
            this.format = format;
        }

        @Override
        public String getAlgorithm() {
            return key.getAlgorithm();
        }

        @Override
        public byte[] getEncoded() {
            return key.getEncoded();
        }

        @Override
        public String getFormat() {
            return format;
        }
    }

    class MyRSAPrivateKey implements PrivateKey {
        private PrivateKey key;
        private String format;

        MyRSAPrivateKey(PrivateKey key) {
            this(key, key.getFormat());
        }

        MyRSAPrivateKey(PrivateKey key, String format) {
            assertEquals(key.getAlgorithm(), "RSA");
            this.key = key;
            this.format = format;
        }

        @Override
        public String getAlgorithm() {
            return key.getAlgorithm();
        }

        @Override
        public byte[] getEncoded() {
            return key.getEncoded();
        }

        @Override
        public String getFormat() {
            return format;
        }
    }
}
