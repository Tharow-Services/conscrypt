/*
 * Copyright (C) 2009 The Android Open Source Project
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
package org.conscrypt.java.security;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyFactoryTestRSA extends
        AbstractKeyFactoryTest<RSAPublicKeySpec, RSAPrivateKeySpec> {

    public KeyFactoryTestRSA() {
        super("RSA", RSAPublicKeySpec.class, RSAPrivateKeySpec.class);
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new CipherAsymmetricCryptHelper("RSA").test(keyPair);
    }

    @Test
    public void testExtraBufferSpace_Private() throws Exception {
        ServiceTester.test("KeyFactory")
            .withAlgorithm("RSA")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    PrivateKey privateKey = DefaultKeys.getPrivateKey("RSA");
                    byte[] encoded = privateKey.getEncoded();
                    byte[] longBuffer = new byte[encoded.length + 147];
                    System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
                    KeyFactory.getInstance(algorithm, p).generatePrivate(
                        new PKCS8EncodedKeySpec(longBuffer));
                }
            });
    }

    @Test
    public void testExtraBufferSpace_Public() throws Exception {
        ServiceTester.test("KeyFactory")
            .withAlgorithm("RSA")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    PublicKey publicKey = DefaultKeys.getPublicKey("RSA");
                    byte[] encoded = publicKey.getEncoded();
                    byte[] longBuffer = new byte[encoded.length + 147];
                    System.arraycopy(encoded, 0, longBuffer, 0, encoded.length);
                    KeyFactory.getInstance(algorithm, p).generatePublic(
                        new X509EncodedKeySpec(longBuffer));
                }
            });
    }
}
