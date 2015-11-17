/*
 * Copyright (C) 2008 The Android Open Source Project
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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Implements the subset of the JDK Signature interface needed for
 * signature verification using OpenSSL.
 */
public class OpenSSLSignature extends SignatureSpi {
    private static enum EngineType {
        RSA, EC,
    }

    private NativeRef.EVP_MD_CTX ctx;

    /**
     * The current OpenSSL key we're operating on.
     */
    private OpenSSLKey key;

    /**
     * Holds the type of the Java algorithm.
     */
    private final EngineType engineType;

    /**
     * Digest algorithm (reference to {@code EVP_MD}).
     */
    private final long evpMdRef;

    /**
     * Holds a dummy buffer for writing single bytes to the digest.
     */
    private final byte[] singleByte = new byte[1];

    /**
     * True when engine is initialized to signing.
     */
    private boolean signing;

    private long evpPkeyCtx;

    /**
     * Creates a new OpenSSLSignature instance for the given algorithm name.
     *
     * @param evpMdRef digest algorithm ({@code EVP_MD} reference).
     */
    private OpenSSLSignature(long evpMdRef, EngineType engineType) {
        this.engineType = engineType;
        this.evpMdRef = evpMdRef;
    }

    private final void resetContext() {
        NativeRef.EVP_MD_CTX ctxLocal = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        if (signing) {
            enableDSASignatureNonceHardeningIfApplicable();
            evpPkeyCtx = NativeCrypto.EVP_DigestSignInit(ctxLocal, evpMdRef, key.getNativeRef());
        } else {
            evpPkeyCtx = NativeCrypto.EVP_DigestVerifyInit(ctxLocal, evpMdRef, key.getNativeRef());
        }
        configureEVP_PKEY_CTX(evpPkeyCtx);
        this.ctx = ctxLocal;
    }

    /**
     * Configures the {@code EVP_PKEY_CTX} associated with this operation.
     *
     * <p>The default implementation does nothing.
     *
     * @param ctx reference to the {@code EVP_PKEY_CTX}.
     */
    protected void configureEVP_PKEY_CTX(long ctx) {}

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (signing) {
            NativeCrypto.EVP_DigestSignUpdate(ctxLocal, input, offset, len);
        } else {
            NativeCrypto.EVP_DigestVerifyUpdate(ctxLocal, input, offset, len);
        }
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        // Optimization: Avoid copying/allocation for direct buffers because their contents are
        // stored as a contiguous region in memory and thus can be efficiently accessed from native
        // code.

        if (!input.hasRemaining()) {
            return;
        }

        if (!input.isDirect()) {
            super.engineUpdate(input);
            return;
        }

        long baseAddress = NativeCrypto.getDirectBufferAddress(input);
        if (baseAddress == 0) {
            // Direct buffer's contents can't be accessed from JNI  -- superclass's implementation
            // is good enough to handle this.
            super.engineUpdate(input);
            return;
        }

        // Process the contents between Buffer's position and limit (remaining() number of bytes)
        int position = input.position();
        long ptr = baseAddress + position;
        if (ptr < baseAddress) {
            throw new RuntimeException("Start pointer overflow");
        }

        int len = input.remaining();
        if (ptr + len < ptr) {
            throw new RuntimeException("End pointer overflow");
        }

        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        if (signing) {
            NativeCrypto.EVP_DigestSignUpdateDirect(ctxLocal, ptr, len);
        } else {
            NativeCrypto.EVP_DigestVerifyUpdateDirect(ctxLocal, ptr, len);
        }
        input.position(position + len);
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private void checkEngineType(OpenSSLKey pkey) throws InvalidKeyException {
        final int pkeyType = NativeCrypto.EVP_PKEY_type(pkey.getNativeRef());

        switch (engineType) {
            case RSA:
                if (pkeyType != NativeConstants.EVP_PKEY_RSA) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not RSA)");
                }
                break;
            case EC:
                if (pkeyType != NativeConstants.EVP_PKEY_EC) {
                    throw new InvalidKeyException("Signature initialized as " + engineType
                            + " (not EC)");
                }
                break;
            default:
                throw new InvalidKeyException("Key must be of type " + engineType);
        }
    }

    private void initInternal(OpenSSLKey newKey, boolean signing) throws InvalidKeyException {
        checkEngineType(newKey);
        key = newKey;

        this.signing = signing;
        resetContext();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPrivateKey(privateKey), true);
    }

    /**
     * Enables a mitigation against private key leakage through ECDSA
     * signatures when weak nonces (per-message k values) are used. To mitigate
     * the issue, private key and message being signed is mixed into the
     * randomly generated nonce (k).
     *
     * <p>Does nothing for signatures that are not ECDSA.
     */
    private void enableDSASignatureNonceHardeningIfApplicable() {
        final OpenSSLKey key = this.key;
        switch (engineType) {
            case EC:
                NativeCrypto.EC_KEY_set_nonce_from_hash(key.getNativeRef(), true);
                break;
            default:
                // Hardening not applicable
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        initInternal(OpenSSLKey.fromPublicKey(publicKey), false);
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        try {
            return NativeCrypto.EVP_DigestSignFinal(ctxLocal);
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after sign
             * calls.
             */
            resetContext();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        final NativeRef.EVP_MD_CTX ctxLocal = ctx;
        try {
            return NativeCrypto.EVP_DigestVerifyFinal(ctxLocal, sigBytes, 0, sigBytes.length);
        } catch (Exception ex) {
            throw new SignatureException(ex);
        } finally {
            /*
             * Java expects the digest context to be reset completely after
             * verify calls.
             */
            resetContext();
        }
    }

    public static final class MD5RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("MD5");
        public MD5RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA1RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA1");
        public SHA1RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA224RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA224");
        public SHA224RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA256RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA256");
        public SHA256RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA384RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA384");
        public SHA384RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA512RSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA512");
        public SHA512RSA() {
            super(EVP_MD, EngineType.RSA);
        }
    }
    public static final class SHA1ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA1");
        public SHA1ECDSA() {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA224ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA224");
        public SHA224ECDSA() {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA256ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA256");
        public SHA256ECDSA() {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA384ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA384");
        public SHA384ECDSA() {
            super(EVP_MD, EngineType.EC);
        }
    }
    public static final class SHA512ECDSA extends OpenSSLSignature {
        private static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("SHA512");
        public SHA512ECDSA() {
            super(EVP_MD, EngineType.EC);
        }
    }
}

