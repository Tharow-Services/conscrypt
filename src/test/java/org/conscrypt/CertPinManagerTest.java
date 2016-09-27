/*
 * Copyright (C) 2012 The Android Open Source Project
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

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import junit.framework.TestCase;
import libcore.java.security.TestKeyStore;

public class CertPinManagerTest extends TestCase {

    private List<X509Certificate> expectedFullChain;
    private X509Certificate[] chain;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        KeyStore.PrivateKeyEntry pke = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
        X509Certificate[] certs = (X509Certificate[]) pke.getCertificateChain();
        expectedFullChain = Arrays.asList(certs);
        // Leave the root out of the chain
        chain = new X509Certificate[2];
        chain[0] = certs[0];
        chain[1] = certs[1];
    }

    public void testCertPinManagerCalled() throws Exception {
        boolean called = false;
        CertPinManager manager = new CertPinManager() {
            @Override
            public boolean isChainValid(String hostname, List<X509Certificate> chain) {
                called = true;
                return true;
            }
        }
        callCheckServerTrusted(null, manager);
        assertTrue(called);
    }

    public void testFailure() throws Exception {
        CertPinManager manager = new CertPinManager() {
            @Override
            public boolean isChainValid(String hostname, List<X509Certificate> chain) {
                return false;
            }
        }
        try {
            callCheckServerTrusted(null, manager);
            fail("Invalid chain was trusted");
        } catch (CertificateException expected) {
        }
    }

    public void testHostnameProvided() throws Exception {
        final String expectedHostname = "example.com";
        boolean hostnameMatched = false;
        CertPinManager manager = new CertPinManager() {
            @Override
            public boolean isChainValid(String hostname, List<X509Certificate> chain) {
                hostnameMatched = expectedHostname.equals(hostname);
                return true;
            }
        }
        callCheckServerTrusted(null, manager);
        assertTrue(hostnameMatched);
    }

    public void testFullChainProvided() throws Exception {
        boolean fullChainProvided = false;
        CertPinManager manager = new CertPinManager() {
            @Override
            public boolean isChainValid(String hostname, List<X509Certificate> chain) {
                fullChainProvided = expectedFullChain.equals(chain);
                return true;
            }
        }
        callCheckServerTrusted(null, manager);
        assertTrue(fullChainProvided);
    }

    private void callCheckServerTrusted(String hostname, CertPinManager manager)
            throws CertificateException {
        TrustManagerImpl tm = new TrustManagerImpl(TestKeyStore.getClient(), manager);
        tm.checkServerTrusted(chain, "RSA", hostname);
    }
}
