/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License", "www.google.com", 443);
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

package com.android.org.conscrypt;

import static com.android.org.conscrypt.SSLUtils.SessionType.OPEN_SSL_WITH_OCSP;
import static com.android.org.conscrypt.SSLUtils.SessionType.OPEN_SSL_WITH_TLS_SCT;
import static com.android.org.conscrypt.SSLUtils.SessionType.isSupportedType;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * A utility wrapper that abstracts operations on the underlying native SSL_SESSION instance.
 * <p>
 * This is abstract only to support mocking for tests.
 */
abstract class NativeSslSession {
    private static final Logger logger = Logger.getLogger(NativeSslSession.class.getName());

    /**
     * Creates a new instance. Since BoringSSL does not provide an API to get access to all
     * session information via the SSL_SESSION, we get some values (e.g. peer certs) from
     * the {@link ConscryptSession} instead (i.e. the SSL object).
     */
    static NativeSslSession newInstance(NativeRef.SSL_SESSION ref, ConscryptSession session)
            throws SSLPeerUnverifiedException {
        AbstractSessionContext context = (AbstractSessionContext) session.getSessionContext();
        if (context instanceof ClientSessionContext) {
            return new Impl(context, ref, session.getPeerHost(), session.getPeerPort(),
                session.getPeerCertificates(), getOcspResponse(session),
                session.getPeerSignedCertificateTimestamp());
        }

        // Server's will be cached by ID and won't have any of the extra fields.
        return new Impl(context, ref, null, -1, null, null, null);
    }

    private static byte[] getOcspResponse(ConscryptSession session) {
        List<byte[]> ocspResponseList = session.getStatusResponses();
        if (ocspResponseList.size() >= 1) {
            return ocspResponseList.get(0);
        }
        return null;
    }

    /**
     * Creates a new {@link NativeSslSession} instance from the provided serialized bytes, which
     * were generated by {@link #toBytes()}.
     *
     * @return The new instance if successful. If unable to parse the bytes for any reason, returns
     * {@code null}.
     */
    static NativeSslSession newInstance(
            AbstractSessionContext context, byte[] data, String host, int port) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        try {
            int type = buf.getInt();
            if (!isSupportedType(type)) {
                throw new IOException("Unexpected type ID: " + type);
            }

            int length = buf.getInt();
            checkRemaining(buf, length);

            byte[] sessionData = new byte[length];
            buf.get(sessionData);

            int count = buf.getInt();
            checkRemaining(buf, count);

            java.security.cert.X509Certificate[] peerCerts =
                    new java.security.cert.X509Certificate[count];
            for (int i = 0; i < count; i++) {
                length = buf.getInt();
                checkRemaining(buf, length);

                byte[] certData = new byte[length];
                buf.get(certData);
                try {
                    peerCerts[i] = OpenSSLX509Certificate.fromX509Der(certData);
                } catch (Exception e) {
                    throw new IOException("Can not read certificate " + i + "/" + count);
                }
            }

            byte[] ocspData = null;
            if (type >= OPEN_SSL_WITH_OCSP.value) {
                // We only support one OCSP response now, but in the future
                // we may support RFC 6961 which has multiple.
                int countOcspResponses = buf.getInt();
                checkRemaining(buf, countOcspResponses);

                if (countOcspResponses >= 1) {
                    int ocspLength = buf.getInt();
                    checkRemaining(buf, ocspLength);

                    ocspData = new byte[ocspLength];
                    buf.get(ocspData);

                    // Skip the rest of the responses.
                    for (int i = 1; i < countOcspResponses; i++) {
                        ocspLength = buf.getInt();
                        checkRemaining(buf, ocspLength);
                        buf.position(buf.position() + ocspLength);
                    }
                }
            }

            byte[] tlsSctData = null;
            if (type == OPEN_SSL_WITH_TLS_SCT.value) {
                int tlsSctDataLength = buf.getInt();
                checkRemaining(buf, tlsSctDataLength);

                if (tlsSctDataLength > 0) {
                    tlsSctData = new byte[tlsSctDataLength];
                    buf.get(tlsSctData);
                }
            }

            if (buf.remaining() != 0) {
                log(new AssertionError("Read entire session, but data still remains; rejecting"));
                return null;
            }

            NativeRef.SSL_SESSION ref =
                    new NativeRef.SSL_SESSION(NativeCrypto.d2i_SSL_SESSION(sessionData));
            return new Impl(context, ref, host, port, peerCerts, ocspData, tlsSctData);
        } catch (IOException | BufferUnderflowException e) {
            log(e);
            return null;
        }
    }

    abstract byte[] getId();

    abstract boolean isValid();

    /**
     * Returns whether this session should only ever be used for resumption once.
     */
    abstract boolean isSingleUse();

    abstract void offerToResume(NativeSsl ssl) throws SSLException;

    abstract String getCipherSuite();

    abstract String getProtocol();

    abstract String getPeerHost();

    abstract int getPeerPort();

    /**
     * Returns the OCSP stapled response. The returned array is not copied; the caller must
     * either not modify the returned array or make a copy.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6066">RFC 6066</a>
     * @see <a href="https://tools.ietf.org/html/rfc6961">RFC 6961</a>
     */
    abstract byte[] getPeerOcspStapledResponse();

    /**
     * Returns the signed certificate timestamp (SCT) received from the peer. The returned array
     * is not copied; the caller must either not modify the returned array or make a copy.
     *
     * @see <a href="https://tools.ietf.org/html/rfc6962">RFC 6962</a>
     */
    abstract byte[] getPeerSignedCertificateTimestamp();

    /**
     * Converts the given session to bytes.
     *
     * @return session data as bytes or null if the session can't be converted
     */
    abstract byte[] toBytes();

    /**
     * Converts this object to a {@link SSLSession}. The returned session will support only a
     * subset of the {@link SSLSession} API.
     */
    abstract SSLSession toSSLSession();

    /**
     * The session wrapper implementation.
     */
    private static final class Impl extends NativeSslSession {
        private final NativeRef.SSL_SESSION ref;

        // BoringSSL offers no API to obtain these values directly from the SSL_SESSION.
        private final AbstractSessionContext context;
        private final String host;
        private final int port;
        private final String protocol;
        private final String cipherSuite;
        private final java.security.cert.X509Certificate[] peerCertificates;
        private final byte[] peerOcspStapledResponse;
        private final byte[] peerSignedCertificateTimestamp;

        private Impl(AbstractSessionContext context, NativeRef.SSL_SESSION ref, String host,
                int port, java.security.cert.X509Certificate[] peerCertificates,
                byte[] peerOcspStapledResponse, byte[] peerSignedCertificateTimestamp) {
            this.context = context;
            this.host = host;
            this.port = port;
            this.peerCertificates = peerCertificates;
            this.peerOcspStapledResponse = peerOcspStapledResponse;
            this.peerSignedCertificateTimestamp = peerSignedCertificateTimestamp;
            this.protocol = NativeCrypto.SSL_SESSION_get_version(ref.address);
            this.cipherSuite =
                    NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_SESSION_cipher(ref.address));
            this.ref = ref;
        }

        @Override
        byte[] getId() {
            return NativeCrypto.SSL_SESSION_session_id(ref.address);
        }

        private long getCreationTime() {
            return NativeCrypto.SSL_SESSION_get_time(ref.address);
        }

        @Override
        boolean isValid() {
            long creationTimeMillis = getCreationTime();
            // Use the minimum of the timeout from the context and the session.
            long timeoutMillis = Math.max(0,
                                         Math.min(context.getSessionTimeout(),
                                                 NativeCrypto.SSL_SESSION_get_timeout(ref.address)))
                    * 1000;
            return (System.currentTimeMillis() - timeoutMillis) < creationTimeMillis;
        }

        @Override
        boolean isSingleUse() {
            return NativeCrypto.SSL_SESSION_should_be_single_use(ref.address);
        }

        @Override
        void offerToResume(NativeSsl ssl) throws SSLException {
            ssl.offerToResumeSession(ref.address);
        }

        @Override
        String getCipherSuite() {
            return cipherSuite;
        }

        @Override
        String getProtocol() {
            return protocol;
        }

        @Override
        String getPeerHost() {
            return host;
        }

        @Override
        int getPeerPort() {
            return port;
        }

        @Override
        byte[] getPeerOcspStapledResponse() {
            return peerOcspStapledResponse;
        }

        @Override
        byte[] getPeerSignedCertificateTimestamp() {
            return peerSignedCertificateTimestamp;
        }

        @Override
        byte[] toBytes() {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream daos = new DataOutputStream(baos);

                daos.writeInt(OPEN_SSL_WITH_TLS_SCT.value); // session type ID

                // Session data.
                byte[] data = NativeCrypto.i2d_SSL_SESSION(ref.address);
                daos.writeInt(data.length);
                daos.write(data);

                // Certificates.
                daos.writeInt(peerCertificates.length);

                for (Certificate cert : peerCertificates) {
                    data = cert.getEncoded();
                    daos.writeInt(data.length);
                    daos.write(data);
                }

                if (peerOcspStapledResponse != null) {
                    daos.writeInt(1);
                    daos.writeInt(peerOcspStapledResponse.length);
                    daos.write(peerOcspStapledResponse);
                } else {
                    daos.writeInt(0);
                }

                if (peerSignedCertificateTimestamp != null) {
                    daos.writeInt(peerSignedCertificateTimestamp.length);
                    daos.write(peerSignedCertificateTimestamp);
                } else {
                    daos.writeInt(0);
                }

                // TODO: local certificates?

                return baos.toByteArray();
            } catch (IOException e) {
                // TODO(nathanmittler): Better error handling?
                logger.log(Level.FINE, "Failed to convert saved SSL Session: ", e);
                return null;
            } catch (CertificateEncodingException e) {
                log(e);
                return null;
            }
        }

        @Override
        SSLSession toSSLSession() {
            return new SSLSession() {
                @Override
                public byte[] getId() {
                    return Impl.this.getId();
                }

                @Override
                public String getCipherSuite() {
                    return Impl.this.getCipherSuite();
                }

                @Override
                public String getProtocol() {
                    return Impl.this.getProtocol();
                }

                @Override
                public String getPeerHost() {
                    return Impl.this.getPeerHost();
                }

                @Override
                public int getPeerPort() {
                    return Impl.this.getPeerPort();
                }

                @Override
                public long getCreationTime() {
                    return Impl.this.getCreationTime();
                }

                @Override
                public boolean isValid() {
                    return Impl.this.isValid();
                }

                // UNSUPPORTED OPERATIONS

                @Override
                public SSLSessionContext getSessionContext() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public long getLastAccessedTime() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void invalidate() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void putValue(String s, Object o) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Object getValue(String s) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void removeValue(String s) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public String[] getValueNames() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Certificate[] getPeerCertificates() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Certificate[] getLocalCertificates() {
                    throw new UnsupportedOperationException();
                }

                @Override
                @SuppressWarnings("deprecation")
                public javax.security.cert.X509Certificate[] getPeerCertificateChain() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Principal getPeerPrincipal() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Principal getLocalPrincipal() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public int getPacketBufferSize() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public int getApplicationBufferSize() {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }

    private static void log(Throwable t) {
        // TODO(nathanmittler): Better error handling?
        logger.log(Level.FINE, "Error inflating SSL session: {0}",
                (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
    }

    private static void checkRemaining(ByteBuffer buf, int length) throws IOException {
        if (length < 0) {
            throw new IOException("Length is negative: " + length);
        }
        if (length > buf.remaining()) {
            throw new IOException(
                    "Length of blob is longer than available: " + length + " > " + buf.remaining());
        }
    }
}
