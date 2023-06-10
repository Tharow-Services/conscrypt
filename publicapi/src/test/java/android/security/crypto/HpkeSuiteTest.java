/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.security.crypto;

import static com.android.org.conscrypt.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class HpkeSuiteTest {
    @Test
    public void testToConscryptSuite_DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM()
            throws Exception {
        final HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM;
        final Hpke hpke = new Hpke(suite);

        hpke.setupBaseRecipient(
                /* enc= */ decodeHex(
                        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
                /* sk= */
                createPrivateKey(decodeHex(
                        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")),
                /* info= */ decodeHex("4f6465206f6e2061204772656369616e2055726e"));

        byte[] pt = hpke.open(
                /* ct= */ decodeHex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97ba"
                        + "bc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
                /* aad= */ decodeHex("436f756e742d30"));

        assertArrayEquals(
                decodeHex("4265617574792069732074727574682c20747275746820626561757479"), pt);
    }

    @Test
    public void testToConscryptSuite_DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM()
            throws Exception {
        HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM;
        final Hpke hpke = new Hpke(suite);

        hpke.setupBaseRecipient(
                /* enc= */ decodeHex(
                        "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"),
                /* sk= */
                createPrivateKey(decodeHex(
                        "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d")),
                /* info= */ decodeHex("4f6465206f6e2061204772656369616e2055726e"));

        byte[] pt = hpke.open(
                /* ct= */ decodeHex("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5"
                        + "f512be9931980a41de125a925cdad859d5b7a"),
                /* aad= */ decodeHex("436f756e742d30"));

        assertArrayEquals(
                decodeHex("4265617574792069732074727574682c20747275746820626561757479"), pt);
    }

    @Test
    public void testToConscryptSuite_DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305()
            throws Exception {
        HpkeSuite suite = HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305;
        final Hpke hpke = new Hpke(suite);

        hpke.setupBaseRecipient(
                /* enc= */ decodeHex(
                        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"),
                /* sk= */
                createPrivateKey(decodeHex(
                        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")),
                /* info= */ decodeHex("4f6465206f6e2061204772656369616e2055726e"));

        byte[] pt = hpke.open(
                /* ct= */ decodeHex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0d"
                        + "ef8c8b60b4db21993c62ce81883d2dd1b51a28"),
                /* aad= */ decodeHex("436f756e742d30"));

        assertArrayEquals(
                decodeHex("4265617574792069732074727574682c20747275746820626561757479"), pt);
    }

    private static PrivateKey createPrivateKey(byte[] privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory factory = KeyFactory.getInstance("XDH");
        final KeySpec spec = new SecretKeySpec(privateKey, "RAW");
        return factory.generatePrivate(spec);
    }
}
