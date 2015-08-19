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

import org.conscrypt.OpenSSLKey;
import org.conscrypt.OpenSSLX509Certificate;
import junit.framework.TestCase;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Set;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;

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

    private static final OpenSSLX509Certificate CA;
    private static final OpenSSLX509Certificate CERT;
    private static final OpenSSLX509Certificate CERT_EMBEDDED;
    private static final CTVerifier CT_VERIFIER;
    static {
        try {
            CA = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
            CERT = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
            CERT_EMBEDDED = OpenSSLX509Certificate.fromX509PemInputStream(
                    openTestFile("cert-ct-embedded.pem"));

            PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(
                    openTestFile("ct-server-key-public.pem")).getPublicKey();
            CTLogStore store = new CTLogStoreImpl(new CTLogInfo[] {
                new CTLogInfo(key, "Test Log", "foo")
            });
            CT_VERIFIER = new CTVerifier(store);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };

    public void test_verifyCertificateTransparency_withOCSPResponse() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] ocspResponse = readTestFile("ocsp-response.der");
        Set<CTLogInfo> logs = CT_VERIFIER.verifyCertificateTransparency(chain, null, ocspResponse);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_withTLSExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
        Set<CTLogInfo> logs = CT_VERIFIER.verifyCertificateTransparency(chain, tlsExtension, null);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_withEmbeddedExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT_EMBEDDED, CA };

        Set<CTLogInfo> logs = CT_VERIFIER.verifyCertificateTransparency(chain, null, null);
        assertFalse(logs.isEmpty());
    }

    public void test_verifyCertificateTransparency_failMissingTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        try {
            CT_VERIFIER.verifyCertificateTransparency(chain, null, null);
            fail("CTVerificationException not thrown.");
        } catch (CTVerificationException e) {
        }
    }

    public void test_verifyCertificateTransparency_failInvalidTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");

        try {
            CT_VERIFIER.verifyCertificateTransparency(chain, tlsExtension, null);
            fail("CTVerificationException not thrown.");
        } catch (CTVerificationException e) {
        }
    }
}

