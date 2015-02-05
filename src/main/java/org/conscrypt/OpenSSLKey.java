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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;

public class OpenSSLKey {
    private final NativeRef.EVP_PKEY ctx;

    private final OpenSSLEngine engine;

    private final String alias;

    private final boolean wrapped;

    public OpenSSLKey(long ctx) {
        this(ctx, false);
    }

    public OpenSSLKey(long ctx, boolean wrapped) {
        this.ctx = new NativeRef.EVP_PKEY(ctx);
        engine = null;
        alias = null;
        this.wrapped = wrapped;
    }

    public OpenSSLKey(long ctx, OpenSSLEngine engine, String alias) {
        this.ctx = new NativeRef.EVP_PKEY(ctx);
        this.engine = engine;
        this.alias = alias;
        this.wrapped = false;
    }

    /**
     * Returns the EVP_PKEY context for use in JNI calls.
     */
    public NativeRef.EVP_PKEY getNativeRef() {
        return ctx;
    }

    OpenSSLEngine getEngine() {
        return engine;
    }

    boolean isEngineBased() {
        return engine != null;
    }

    public String getAlias() {
        return alias;
    }

    public boolean isWrapped() {
        return wrapped;
    }

    /**
     * Obtains an {@code OpenSSLKey} corresponding to the provided private key.
     */
    public static OpenSSLKey fromPrivateKey(PrivateKey key) throws InvalidKeyException {
        if (key instanceof OpenSSLKeyHolder) {
            // The key is from this provider
            return ((OpenSSLKeyHolder) key).getOpenSSLKey();
        }

        if ("RSA".equals(key.getAlgorithm())) {
            // Check whether the key is an old platform key backed by OpenSSL.
            OpenSSLKey wrapper = Platform.wrapRsaKey(key);
            if (wrapper != null) {
                return wrapper;
            }
        }
        // The key is not backed by OpenSSL. It needs to be imported (via its PKCS#8 form) into this
        // provider.

        String keyFormat = key.getFormat();
        if ("PKCS#8".equals(keyFormat)) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key encoding is null");
            }
            return new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(encoded));
        }

        if (keyFormat == null) {
            throw new InvalidKeyException("Opaque keys cannot be imported");
        } else {
            throw new InvalidKeyException("Unsupported key format for import: " + keyFormat);
        }
    }

    /**
     * Obtains an {@code OpenSSLKey} corresponding to the provided private key for use in this
     * provider's TLS/SSL stack only. The optional public key can be helpful for adapting opaque
     * private keys from other providers. The resulting key is not guaranteed to work
     * outside of the TLS/SSL stack (e.g., in JCA crypto primitives).
     *
     * @param privateKey private key.
     * @param publicKey corresponding public key or {@code null} if not available.
     */
    public static OpenSSLKey fromPrivateKeyForTlsStackOnly(
            PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException {
        if (privateKey instanceof OpenSSLKeyHolder) {
            // The key is from this provider
            return ((OpenSSLKeyHolder) privateKey).getOpenSSLKey();
        }

        if ("RSA".equals(privateKey.getAlgorithm())) {
            // Check whether the key is an old platform key backed by OpenSSL.
            OpenSSLKey wrapper = Platform.wrapRsaKey(privateKey);
            if (wrapper != null) {
                return wrapper;
            }
        }
        // The key is not yet backed by OpenSSSL. It needs to wrapped or imported (via its PKCS#8
        // form).

        String keyFormat = privateKey.getFormat();
        if (keyFormat == null) {
            // This is an opaque key (it does not expose its key material). Wrap it so that TLS/SSL
            // stack's operations on the key are delegated to the key provider's Signature/Cipher
            // implementations.
            return wrapOpaquePrivateKey(privateKey, publicKey);
        }

        if ("PKCS#8".equals(keyFormat)) {
            // The key can export its key material. Import the key into this provider.
            byte[] encoded = privateKey.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key encoding is null");
            }
            return new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(encoded));
        }

        throw new InvalidKeyException("Unsupported key format for import: " + keyFormat);
    }

    /**
     * Obtains an {@code OpenSSLKey} corresponding to the provided EC private key and EC parameters
     * for use in this provider's TLS/SSL stack only. The resulting key is not guaranteed to work
     * outside of the TLS/SSL stack (e.g., in JCA crypto primitives).
     *
     * <p>
     * The parameters are required for adapting the key to OpenSSL. If you have the public key, use
     * {@link #fromPrivateKeyForTlsStackOnly(PrivateKey, PublicKey)} instead.
     */
    public static OpenSSLKey fromECPrivateKeyForTlsStackOnly(
            PrivateKey privateKey, ECParameterSpec ecParameters) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("key == null");
        }
        if (!"EC".equals(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("Not an EC key: " + privateKey.getAlgorithm());
        }
        if (privateKey instanceof OpenSSLKeyHolder) {
            return ((OpenSSLKeyHolder) privateKey).getOpenSSLKey();
        }

        final String keyFormat = privateKey.getFormat();
        if (keyFormat == null) {
            return OpenSSLECPrivateKey.wrapPlatformKey(privateKey, ecParameters);
        } else if (!"PKCS#8".equals(keyFormat)) {
            throw new InvalidKeyException("Unknown key format: " + keyFormat);
        }

        final byte[] encoded = privateKey.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        return new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(encoded));
    }

    private static OpenSSLKey wrapOpaquePrivateKey(PrivateKey privateKey, PublicKey publicKey)
            throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("key == null");
        }
        String algorithm = privateKey.getAlgorithm();
        if ("RSA".equals(algorithm)) {
            return OpenSSLRSAPrivateKey.wrapPlatformKey(privateKey, publicKey);
        } else if ("EC".equals(algorithm)) {
            return OpenSSLECPrivateKey.wrapPlatformKey(privateKey, publicKey);
        } else {
            throw new InvalidKeyException("Unknown key type: " + privateKey.getAlgorithm()
                    + ": " + privateKey);
        }
    }

    public static OpenSSLKey fromPublicKey(PublicKey key) throws InvalidKeyException {
        if (key instanceof OpenSSLKeyHolder) {
            return ((OpenSSLKeyHolder) key).getOpenSSLKey();
        }

        if (!"X.509".equals(key.getFormat())) {
            throw new InvalidKeyException("Unknown key format " + key.getFormat());
        }

        final byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key encoding is null");
        }

        return new OpenSSLKey(NativeCrypto.d2i_PUBKEY(key.getEncoded()));
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeCrypto.EVP_PKEY_RSA:
                return new OpenSSLRSAPublicKey(this);
            case NativeCrypto.EVP_PKEY_DH:
                return new OpenSSLDHPublicKey(this);
            case NativeCrypto.EVP_PKEY_EC:
                return new OpenSSLECPublicKey(this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    static PublicKey getPublicKey(X509EncodedKeySpec keySpec, int type)
            throws InvalidKeySpecException {
        X509EncodedKeySpec x509KeySpec = keySpec;

        final OpenSSLKey key;
        try {
            key = new OpenSSLKey(NativeCrypto.d2i_PUBKEY(x509KeySpec.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }

        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef()) != type) {
            throw new InvalidKeySpecException("Unexpected key type");
        }

        try {
            return key.getPublicKey();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeCrypto.EVP_PKEY_RSA:
                return new OpenSSLRSAPrivateKey(this);
            case NativeCrypto.EVP_PKEY_DH:
                return new OpenSSLDHPrivateKey(this);
            case NativeCrypto.EVP_PKEY_EC:
                return new OpenSSLECPrivateKey(this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    static PrivateKey getPrivateKey(PKCS8EncodedKeySpec keySpec, int type)
            throws InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8KeySpec = keySpec;

        final OpenSSLKey key;
        try {
            key = new OpenSSLKey(NativeCrypto.d2i_PKCS8_PRIV_KEY_INFO(pkcs8KeySpec.getEncoded()));
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }

        if (NativeCrypto.EVP_PKEY_type(key.getNativeRef()) != type) {
            throw new InvalidKeySpecException("Unexpected key type");
        }

        try {
            return key.getPrivateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public SecretKey getSecretKey(String algorithm) throws NoSuchAlgorithmException {
        switch (NativeCrypto.EVP_PKEY_type(ctx)) {
            case NativeCrypto.EVP_PKEY_HMAC:
            case NativeCrypto.EVP_PKEY_CMAC:
                return new OpenSSLSecretKey(algorithm, this);
            default:
                throw new NoSuchAlgorithmException("unknown PKEY type");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (!(o instanceof OpenSSLKey)) {
            return false;
        }

        OpenSSLKey other = (OpenSSLKey) o;
        if (ctx.equals(other.getNativeRef())) {
            return true;
        }

        /*
         * ENGINE-based keys must be checked in a special way.
         */
        if (engine == null) {
            if (other.getEngine() != null) {
                return false;
            }
        } else if (!engine.equals(other.getEngine())) {
            return false;
        } else {
            if (alias != null) {
                return alias.equals(other.getAlias());
            } else if (other.getAlias() != null) {
                return false;
            }
        }

        return NativeCrypto.EVP_PKEY_cmp(ctx, other.getNativeRef()) == 1;
    }

    @Override
    public int hashCode() {
        int hash = 1;
        hash = hash * 17 + ctx.hashCode();
        hash = hash * 31 + (int) (engine == null ? 0 : engine.getEngineContext());
        return hash;
    }
}
