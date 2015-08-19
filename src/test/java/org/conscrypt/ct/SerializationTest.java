/*
 * Copyright 2014 The Android Open Source Project
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
import java.util.Arrays;

import static org.conscrypt.TestUtils.openTestFile;

public class SerializationTest extends TestCase {
    public void test_decode_SignedCertificateTimestamp() throws Exception {
        InputStream in = openTestFile("ct-signed-timestamp");
        SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(in);

        assertEquals(CTConstants.SCT_VERSION_V1, sct.getVersion());
        assertEquals(1441720670000L, sct.getTimestamp());
        assertEquals(0, sct.getExtensions().length);
        assertEquals(DigitallySigned.HashAlgorithm.SHA256,
                     sct.getSignature().getHashAlgorithm());
        assertEquals(DigitallySigned.SignatureAlgorithm.ECDSA,
                     sct.getSignature().getSignatureAlgorithm());
    }

    public void test_decode_DigitallySigned() throws Exception {
        InputStream in = new ByteArrayInputStream(new byte[] {
            0x04, 0x03,            // hash & signature algorithm
            0x00, 0x04,            // signature length
            0x12, 0x34, 0x56, 0x78 // signature
        });

        DigitallySigned dst = DigitallySigned.decode(in);
        assertEquals(DigitallySigned.HashAlgorithm.SHA256, dst.getHashAlgorithm());
        assertEquals(DigitallySigned.SignatureAlgorithm.ECDSA, dst.getSignatureAlgorithm());
        assertEqualByteArrays(new byte[] { 0x12, 0x34, 0x56, 0x78}, dst.getSignature());
    }

    public void test_encode_LogEntry_X509Certificate() throws Exception {
        // Use a dummy certificate. It doesn't matter, LogEntry doesn't care about the contents.
        LogEntry entry = LogEntry.createForX509Certificate(new byte[] { 0x12, 0x34, 0x56, 0x78 });
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        entry.encode(output);

        assertEqualByteArrays(new byte[] {
            0x00, 0x00,            // entry_type
            0x00, 0x00, 0x04,      // x509_entry length
            0x12, 0x34, 0x56, 0x78 // x509_entry
        }, output.toByteArray());
    }

    public void test_encode_LogEntry_PreCertificate() throws Exception {
        // Use a dummy certificate and issuer key hash. It doesn't matter,
        // LogEntry doesn't care about the contents.
        LogEntry entry = LogEntry.createForPrecertificate(new byte[] { 0x12, 0x34, 0x56, 0x78 },
                                                          new byte[32]);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        entry.encode(output);

        assertEqualByteArrays(new byte[] {
            0x00, 0x01,                      // entry_type
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // issuer key hash
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0x00, 0x00, 0x04,                // precert_entry length
            0x12, 0x34, 0x56, 0x78           // precert_entry
        }, output.toByteArray());
    }

    public static void assertEqualByteArrays(byte[] expected, byte[] actual) {
        assertEquals(Arrays.toString(expected), Arrays.toString(actual));
    }
}

