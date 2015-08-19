/*
 * Copyright (C) 2015 The Android Open Source Project
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

import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLKey;
import org.conscrypt.OpenSSLX509Certificate;
import junit.framework.TestCase;
import java.security.PublicKey;
import java.util.Arrays;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;

public class CTVerifierTest extends TestCase {
    private OpenSSLX509Certificate CA;
    private OpenSSLX509Certificate CERT;
    private OpenSSLX509Certificate CERT_EMBEDDED;
    private CTVerifier CT_VERIFIER;

    @Override
    public void setUp() throws Exception {
        CA = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
        CERT = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
        CERT_EMBEDDED = OpenSSLX509Certificate.fromX509PemInputStream(
                openTestFile("cert-ct-embedded.pem"));

        PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(
                openTestFile("ct-server-key-public.pem")).getPublicKey();
        
        final CTLogInfo log = new CTLogInfo(key, "Test Log", "foo");
        CTLogStore store = new CTLogStore() {
            public CTLogInfo getKnownLog(byte[] logId) {
                if (Arrays.equals(logId, log.getID())) {
                    return log;
                } else {
                    return null;
                }
            }
        };

        CT_VERIFIER = new CTVerifier(store);
    }

    public void test_verifySignedCertificateTimestamps_withOCSPResponse() throws Exception {
        // This is only implemented for BoringSSL
        if (!NativeCrypto.isBoringSSL) {
            return;
        }

        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] ocspResponse = readTestFile("ocsp-response.der");
        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, null, ocspResponse);
        assertEquals(1, results.getValidSCTs().size());
        assertEquals(0, results.getInvalidSCTs().size());
    }

    public void test_verifySignedCertificateTimestamps_withTLSExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list");
        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(1, results.getValidSCTs().size());
        assertEquals(0, results.getInvalidSCTs().size());
    }

    public void test_verifySignedCertificateTimestamps_withEmbeddedExtension() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT_EMBEDDED, CA };

        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, null, null);
        assertEquals(1, results.getValidSCTs().size());
        assertEquals(0, results.getInvalidSCTs().size());
    }

    public void test_verifySignedCertificateTimestamps_failMissingTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, null, null);
        assertEquals(0, results.getValidSCTs().size());
        assertEquals(0, results.getInvalidSCTs().size());
    }

    public void test_verifySignedCertificateTimestamps_failInvalidTimestamp() throws Exception {
        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");

        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, tlsExtension, null);
        assertEquals(0, results.getValidSCTs().size());
        assertEquals(1, results.getInvalidSCTs().size());
        assertEquals(SCTVerificationResult.Status.INVALID_SIGNATURE,
                     results.getInvalidSCTs().get(0).status);
    }

    public void test_verifySignedCertificateTimestamps_withMultipleTimestamps() throws Exception {
        // This is only implemented for BoringSSL
        if (!NativeCrypto.isBoringSSL) {
            return;
        }

        OpenSSLX509Certificate[] chain = new OpenSSLX509Certificate[] { CERT, CA };

        byte[] tlsExtension = readTestFile("ct-signed-timestamp-list-invalid");
        byte[] ocspResponse = readTestFile("ocsp-response.der");

        CTResults results = CT_VERIFIER.verifySignedCertificateTimestamps(chain, tlsExtension, ocspResponse);
        assertEquals(1, results.getValidSCTs().size());
        assertEquals(1, results.getInvalidSCTs().size());
        assertEquals(SignedCertificateTimestamp.Origin.OCSP_RESPONSE,
                     results.getValidSCTs().get(0).sct.getOrigin());
        assertEquals(SignedCertificateTimestamp.Origin.TLS_EXTENSION,
                     results.getInvalidSCTs().get(0).sct.getOrigin());
    }
}

