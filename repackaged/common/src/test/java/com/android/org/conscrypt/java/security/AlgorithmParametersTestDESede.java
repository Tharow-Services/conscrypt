/* GENERATED SOURCE. DO NOT MODIFY. */
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
package com.android.org.conscrypt.java.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.android.org.conscrypt.TestUtils;

import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.AlgorithmParameters;
import java.security.Provider;

import javax.crypto.spec.IvParameterSpec;

import tests.util.ServiceTester;

/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class AlgorithmParametersTestDESede extends AbstractAlgorithmParametersTest {

    // BEGIN Android-Added: Allow access to deprecated BC algorithms.
    // Allow access to deprecated BC algorithms in this test, so we can ensure they
    // continue to work
    @ClassRule
    public static TestRule enableDeprecatedBCAlgorithmsRule =
            EnableDeprecatedBouncyCastleAlgorithmsRule.getInstance();
    // END Android-Added: Allow access to deprecated BC algorithms.

    private static final byte[] parameterData = new byte[] {
        (byte) 0x04, (byte) 0x08, (byte) 0x68, (byte) 0xC8,
        (byte) 0xFF, (byte) 0x64, (byte) 0x72, (byte) 0xF5 };

    // See README.ASN1 for how to understand and reproduce this data

    // asn1=FORMAT:HEX,OCTETSTRING:040868C8FF6472F5
    private static final String ENCODED_DATA = "BAgECGjI/2Ry9Q==";

    public AlgorithmParametersTestDESede() {
        super("DESede", new AlgorithmParameterSymmetricHelper("DESede", "CBC/PKCS5PADDING", 112), new IvParameterSpec(parameterData));
    }

    @Test
    public void testEncoding() throws Exception {
        ServiceTester.test("AlgorithmParameters")
            .withAlgorithm("DESEDE")
            .run(new ServiceTester.Test() {
                @Override
                public void test(Provider p, String algorithm) throws Exception {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("DESede", p);

                    params.init(new IvParameterSpec(parameterData));
                    assertEquals(ENCODED_DATA, TestUtils.encodeBase64(params.getEncoded()));

                    params = AlgorithmParameters.getInstance("DESede", p);
                    params.init(TestUtils.decodeBase64(ENCODED_DATA));
                    assertArrayEquals(parameterData,
                        params.getParameterSpec(IvParameterSpec.class).getIV());
                }
            });
    }

}
