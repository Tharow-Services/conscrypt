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
 * limitations under the License
 */

package org.conscrypt;

import junit.framework.TestCase;
import java.io.InputStream;

import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

import static org.conscrypt.TestUtils.assertEqualByteArrays;

public class OpenSSLX509CertificateTest extends TestCase {
    static final String CT_POISON_EXTENSION = "1.3.6.1.4.1.11129.2.4.3";

    private OpenSSLX509Certificate loadTestCertificate(String name) throws ParsingException {
        InputStream is = getClass().getResourceAsStream("/" + name);
        return OpenSSLX509Certificate.fromX509PemInputStream(is);
    }

    public void test_deletingCTPoisonExtension() throws Exception {
        /* preCert has an extra poison extension.
         * If this extension is removed, then the two certificates should have the same TBS.
         */
        OpenSSLX509Certificate preCert = loadTestCertificate("test-embedded-pre-cert.pem");
        OpenSSLX509Certificate simpleCert = loadTestCertificate("test-embedded-simple-cert.pem");

        assertEqualByteArrays(
                preCert.deleteExtension(CT_POISON_EXTENSION).getTBSCertificate(),
                simpleCert.getTBSCertificate());
    }

    public void test_deleteExtensionMakesCopy() throws Exception {
        /* Calling deleteExtension() should not modify the original certificate, only
         * a copy.
         * Make sure the extension is still present in the original object.
         */
        OpenSSLX509Certificate cert = loadTestCertificate("test-embedded-pre-cert.pem");
        assertTrue(cert.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));

        OpenSSLX509Certificate certWithoutExtension = cert.deleteExtension(CT_POISON_EXTENSION);

        assertFalse(certWithoutExtension.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
        assertTrue(cert.getCriticalExtensionOIDs().contains(CT_POISON_EXTENSION));
    }
}

