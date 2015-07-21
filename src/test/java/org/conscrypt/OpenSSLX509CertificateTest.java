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
    static final String CT_SCTLIST_EXTENSION = "1.3.6.1.4.1.11129.2.4.2";
    static final String CT_POISON_EXTENSION = "1.3.6.1.4.1.11129.2.4.3";

    private OpenSSLX509Certificate loadTestCertificate(String name) throws ParsingException {
        InputStream is = getClass().getResourceAsStream("/" + name);
        return OpenSSLX509Certificate.fromX509PemInputStream(is);
    }

    public void test_deleteExtension() throws Exception {
        /*
         * preCert has an extra poison extension.
         * finalCert has an extra SCT list extension.
         * If these two extensions are removed, then the TBS parts of the two
         * certificates should be the same.
         */
        OpenSSLX509Certificate preCert = loadTestCertificate("test-embedded-pre-cert.pem");
        OpenSSLX509Certificate finalCert = loadTestCertificate("test-embedded-cert.pem");

        assertEqualByteArrays(
                preCert.deleteExtension(CT_POISON_EXTENSION).getTBSCertificate(),
                finalCert.deleteExtension(CT_SCTLIST_EXTENSION).getTBSCertificate());
    }
}

