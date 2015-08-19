/*
 * Copyright 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import junit.framework.TestCase;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;

import java.util.Arrays;
import java.util.Set;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;

import org.conscrypt.OpenSSLBIOInputStream;
import org.conscrypt.OpenSSLKey;
import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLX509Certificate;

public class CTVerifierTest extends TestCase {
    static class TestLogStore implements CTLogStore {
        private CTLogInfo log;
        public TestLogStore(CTLogInfo log) {
            this.log = log;
        }

        public CTLogInfo getKnownLog(byte[] logId) {
            if (Arrays.equals(logId, log.getID())) {
                return log;
            }
            return null;
        }
    }

    CTLogStore store;
    CTVerifier verifier;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        InputStream is = openTestFile("ct-server-key-public.pem");
        PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(is).getPublicKey();

        store = new TestLogStore(new CTLogInfo(key, "Test Log", "foo"));
        verifier = new CTVerifier(store);
    }

    public void test_verifyCertificateTransparency_withOCSPResponse() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem")),
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem")),
        };

        byte[] ocspResponse = readTestFile("ocsp-response.der");
        Set<CTLogInfo> logs = verifier.verifyCertificateTransparency(chain, null, ocspResponse);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_withTLSExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem")),
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem")),
        };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
        Set<CTLogInfo> logs = verifier.verifyCertificateTransparency(chain, tlsExtension, null);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_withEmbeddedExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem")),
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem")),
        };

        Set<CTLogInfo> logs = verifier.verifyCertificateTransparency(chain, null, null);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_fail_noTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem")),
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem")),
        };

        try {
            verifier.verifyCertificateTransparency(chain, null, null);
            fail("Exception not thrown.");
        } catch (CTVerificationException e) {
        }
    }

    public void test_verifyCertificateTransparency_fail_invalidTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] {
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem")),
            OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem")),
        };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");

        try {
            verifier.verifyCertificateTransparency(chain, tlsExtension, null);
            fail("Exception not thrown.");
        } catch (CTVerificationException e) {
        }
    }
}

