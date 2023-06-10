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

import com.android.org.conscrypt.Internal;
import java.util.Map;

/**
 * Holds the KEM, KDF, and AEAD that are used and supported by {@link Hpke} defined on
 * RFC 9180.
 *
 * <ul>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism">KEM</a></li>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">KDF</a></li>
 *   <li><a
 * href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">AEAD</a></li>
 * </ul>
 */
public final class HpkeSuite {
    /**
     * {@link HpkeSuite} with the following algorithm scheme:
     * <li>
     *      <ul>KEM:  0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
     *      <ul>KDF:  0x0001: HKDF-SHA256</ul>
     *      <ul>AEAD: 0x0001: AES-128-GCM</ul>
     * </li>
     *
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-encapsulation-mechanism">KEMs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-derivation-functions-kd">KDFs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-authenticated-encryption-wi">AEAD</a>
     */
    public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM =
            new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM);

    /**
     * {@link HpkeSuite} with the following algorithm scheme:
     * <li>
     *      <ul>KEM:  0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
     *      <ul>KDF:  0x0001: HKDF-SHA256</ul>
     *      <ul>AEAD: 0x0002: AES-256-GCM</ul>
     * </li>
     *
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-encapsulation-mechanism">KEMs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-derivation-functions-kd">KDFs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-authenticated-encryption-wi">AEAD</a>
     */
    public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM =
            new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_256_GCM);

    /**
     * {@link HpkeSuite} with the following algorithm scheme:
     * <li>
     *      <ul>KEM  : 0x0020: DHKEM(X25519, HKDF-SHA256)</ul>
     *      <ul>KDF  : 0x0001: HKDF-SHA256</ul>
     *      <ul>AEAD : 0x0003: ChaCha20Poly1305</ul>
     * </li>
     *
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-encapsulation-mechanism">KEMs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-key-derivation-functions-kd">KDFs</a>
     * @see <a
     * href="https://www.rfc-editor.org/rfc/rfc9180
     * .html#name-authenticated-encryption-wi">AEAD</a>
     */
    public static final HpkeSuite DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305 =
            new HpkeSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.CHACHA20POLY1305);

    private static final Map<HpkeSuite, com.android.org.conscrypt.HpkeSuite>
            TO_CONSCRYPT_SUITE_MAP = Map.of(DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM,
                    com.android.org.conscrypt.HpkeSuite
                            .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM,
                    DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
                    com.android.org.conscrypt.HpkeSuite
                            .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
                    DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305,
                    com.android.org.conscrypt.HpkeSuite
                            .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20POLY1305);

    @Internal
    com.android.org.conscrypt.HpkeSuite toConscryptSuite() {
        if (TO_CONSCRYPT_SUITE_MAP.containsKey(this)) {
            return TO_CONSCRYPT_SUITE_MAP.get(this);
        } else {
            throw new IllegalArgumentException("Not supported " + this);
        }
    }

    private final KEM mKem;
    private final KDF mKdf;
    private final AEAD mAead;

    private HpkeSuite(KEM Kem, KDF Kdf, AEAD Aead) {
        mKem = Kem;
        mKdf = Kdf;
        mAead = Aead;
    }

    /**
     * Displays the scheme configured in readable format.
     *
     * @return the scheme configured.
     * @hide
     */
    @Override
    @Internal
    public String toString() {
        return "HpkeSuite{"
                + "mKem=" + mKem + ", mKdf=" + mKdf + ", mAead=" + mAead + '}';
    }

    enum KEM { DHKEM_X25519_HKDF_SHA256 }

    enum KDF { HKDF_SHA256 }

    enum AEAD { AES_128_GCM, AES_256_GCM, CHACHA20POLY1305 }
}
