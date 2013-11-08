/*
 * Copyright 2013 The Android Open Source Project
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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

/**
 *
 */
public class OpenSSLEngineImpl extends SSLEngine implements NativeCrypto.SSLHandshakeCallbacks {
    private final SSLParametersImpl sslParameters;

    /**
     * Protects handshakeStarted and handshakeCompleted.
     */
    private final Object stateLock = new Object();

    private static enum EngineState {
        /**
         * The {@link OpenSSLSocketImpl} object is constructed, but {@link #beginHandshake()}
         * has not yet been called.
         */
        NEW,
        /**
         * {@link #setUseClientMode(boolean)} has been called at least once.
         */
        MODE_SET,
        /**
         * {@link #beginHandshake()} has been called at least once.
         */
        HANDSHAKE_WANTED,
        /**
         * Handshake task has been started.
         */
        HANDSHAKE_STARTED,
        /**
         * Handshake has been completed, but {@link #beginHandshake()} hasn't returned yet.
         */
        HANDSHAKE_COMPLETED,
        /**
         * {@link #beginHandshake()} has completed but the task hasn't
         * been called. This is expected behaviour in cut-through mode, where SSL_do_handshake
         * returns before the handshake is complete. We can now start writing data to the socket.
         */
        READY_HANDSHAKE_CUT_THROUGH,
        /**
         * {@link #beginHandshake()} has completed and socket is ready to go.
         */
        READY,
        CLOSED_INBOUND,
        CLOSED_OUTBOUND,
        /**
         * Inbound and outbound has been called.
         */
        CLOSED,
    }

    // @GuardedBy("stateLock");
    private EngineState engineState = EngineState.NEW;

    /**
     * Protected by synchronizing on stateLock. Starts as 0, set by
     * startHandshake, reset to 0 on close.
     */
    // @GuardedBy("stateLock");
    private long sslNativePointer;

    /** A BIO sink written to only during handshakes. */
    private OpenSSLBIOSink handshakeSink = new OpenSSLBIOSink();

    /** An empty BIO source used during handshaking. */
    private OpenSSLBIOSource handshakeSource = new OpenSSLBIOSource(ByteBuffer.allocateDirect(0));

    /** A BIO sink written to during regular operation. */
    private OpenSSLBIOSink localToRemoteSink = new OpenSSLBIOSink();

    private byte[] mBuffer;

    public OpenSSLEngineImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        this.sslParameters.openSslEnabledProtocols = NativeCrypto.getDefaultProtocols();
        this.sslParameters.openSslEnabledCipherSuites = NativeCrypto.getDefaultCipherSuites();
    }

    public OpenSSLEngineImpl(String host, int port, SSLParametersImpl sslParameters) {
        super(host, port);
        this.sslParameters = sslParameters;
        this.sslParameters.openSslEnabledProtocols = NativeCrypto.getDefaultProtocols();
        this.sslParameters.openSslEnabledCipherSuites = NativeCrypto.getDefaultCipherSuites();
    }

    @Override
    public void beginHandshake() throws SSLException {
        synchronized (stateLock) {
            if (engineState == EngineState.CLOSED) {
                throw new IllegalStateException("Engine has already been closed");
            }
            if (engineState == EngineState.HANDSHAKE_STARTED) {
                throw new IllegalStateException("Handshake has already been started");
            }
            if (engineState != EngineState.MODE_SET) {
                throw new IllegalStateException("Client/server mode must be set before handshake");
            }
            if (getUseClientMode()) {
                engineState = EngineState.HANDSHAKE_WANTED;
            } else {
                engineState = EngineState.HANDSHAKE_STARTED;
            }
        }
        // TODO free resources on failure
        boolean releaseResources = true;
        try {
            final AbstractSessionContext sessionContext = sslParameters.getSessionContext();
            final long sslCtxNativePointer = sessionContext.sslCtxNativePointer;
            sslNativePointer = NativeCrypto.SSL_new(sslCtxNativePointer);
            sslParameters.setSSLParameters(sslCtxNativePointer, sslNativePointer, null,
                    getPeerHost());
            sslParameters.setCertificateValidation(sslNativePointer);
            sslParameters.setTlsChannelId(sslNativePointer);
            if (getUseClientMode()) {
                NativeCrypto.SSL_set_connect_state(sslNativePointer);
            } else {
                NativeCrypto.SSL_set_accept_state(sslNativePointer);
            }
            releaseResources = false;
        } catch (IOException e) {
            throw new SSLException(e);
        } finally {
            if (releaseResources) {
                // TODO actually free resources
            }
        }
    }

    @Override
    public void closeInbound() throws SSLException {
        if (engineState == EngineState.CLOSED) {
            return;
        }
        // TODO anything else?
    }

    @Override
    public void closeOutbound() {
        if (engineState == EngineState.CLOSED) {
            return;
        }
        if (engineState != EngineState.MODE_SET && engineState != EngineState.NEW) {
            // TODO cleanup socket
        }
        engineState = EngineState.CLOSED;
    }

    @Override
    public Runnable getDelegatedTask() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslParameters.getEnabledCipherSuites();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslParameters.getEnabledProtocols();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslParameters.getEnableSessionCreation();
    }

    @Override
    public HandshakeStatus getHandshakeStatus() {
        synchronized (stateLock) {
            switch (engineState) {
                case HANDSHAKE_WANTED:
                    if (getUseClientMode()) {
                        return HandshakeStatus.NEED_WRAP;
                    } else {
                        return HandshakeStatus.NEED_UNWRAP;
                    }
                case HANDSHAKE_STARTED:
                    if (handshakeSink.available() > 0) {
                        return HandshakeStatus.NEED_WRAP;
                    } else {
                        return HandshakeStatus.NEED_UNWRAP;
                    }
                case HANDSHAKE_COMPLETED:
                    if (handshakeSink.available() == 0) {
                        return HandshakeStatus.NOT_HANDSHAKING;
                    } else {
                        return HandshakeStatus.NEED_WRAP;
                    }
                case NEW:
                case MODE_SET:
                case CLOSED:
                case READY:
                case READY_HANDSHAKE_CUT_THROUGH:
                    return HandshakeStatus.NOT_HANDSHAKING;
                default:
                    break;
            }
            throw new IllegalStateException("Unexpected engine state: " + engineState);
        }
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public SSLSession getSession() {
        OpenSSLSessionImpl sslSession = sslParameters.getSession();
        if (sslSession == null) {
            return SSLNullSession.getNullSession();
        }
        return sslSession;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    @Override
    public boolean getUseClientMode() {
        return sslParameters.getUseClientMode();
    }

    @Override
    public boolean getWantClientAuth() {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public boolean isInboundDone() {
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer)
                & NativeCrypto.SSL_RECEIVED_SHUTDOWN) != 0;
    }

    @Override
    public boolean isOutboundDone() {
        return (NativeCrypto.SSL_get_shutdown(sslNativePointer)
                & NativeCrypto.SSL_SENT_SHUTDOWN) != 0;
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslParameters.setEnabledCipherSuites(suites);
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslParameters.setEnabledProtocols(protocols);
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslParameters.setEnableSessionCreation(flag);
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslParameters.setUseClientMode(mode);
        engineState = EngineState.MODE_SET;
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        // If the inbound direction is closed. we can't send anymore.
        if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_INBOUND) {
            return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
        }

        // If we haven't completed the handshake yet, just let the caller know.
        HandshakeStatus handshakeStatus = getHandshakeStatus();
        if (handshakeStatus == HandshakeStatus.NEED_TASK) {
            return new SSLEngineResult(Status.OK, handshakeStatus, 0, 0);
        } else if (handshakeStatus == HandshakeStatus.NEED_UNWRAP) {
            OpenSSLBIOSource source = new OpenSSLBIOSource(src);
            long[] sessionHolder = new long[1];
            int ret;
            try {
                ret = NativeCrypto.SSL_do_handshake_bio(sslNativePointer, sessionHolder,
                        source.getContext(), handshakeSink.getContext(), this, getUseClientMode(),
                        sslParameters.npnProtocols, sslParameters.alpnProtocols);
            } catch (Exception e) {
                throw new SSLHandshakeException(e);
            }
            if (ret == 1) {
                try {
                    sslParameters.setupSession(sessionHolder[0], sslNativePointer, null,
                            getPeerHost(), getPeerPort(), true);
                } catch (IOException e) {
                    throw new SSLHandshakeException(e);
                }
            }
            return new SSLEngineResult(Status.OK, getHandshakeStatus(), 0, 0);
        }

        try {
            byte[] buffer = mBuffer;
            if (buffer == null) {
                buffer = new byte[8192];
                mBuffer = buffer;
            }

            ByteBuffer srcDuplicate = src.duplicate();
            OpenSSLBIOSource source = new OpenSSLBIOSource(srcDuplicate);
            /*
             * We can't just use .mark() here because the caller might be using
             * it.
             */
            int numRead = NativeCrypto.SSL_read_BIO(sslNativePointer, buffer, source.getContext(),
                    localToRemoteSink.getContext(), this);
            src.position(srcDuplicate.position());

            return new SSLEngineResult(Status.OK, getHandshakeStatus(), numRead,
                    writeBytesToByteBuffers(buffer, numRead, dsts));
        } catch (IOException e) {
            throw new SSLException(e);
        }
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
            throws SSLException {
        // If the outbound direction is closed. we can't send anymore.
        if (engineState == EngineState.CLOSED || engineState == EngineState.CLOSED_OUTBOUND) {
            return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
        }

        // If we haven't completed the handshake yet, just let the caller know.
        HandshakeStatus handshakeStatus = getHandshakeStatus();
        if (handshakeStatus == HandshakeStatus.NEED_TASK) {
            return new SSLEngineResult(Status.OK, handshakeStatus, 0, 0);
        } else if (handshakeStatus == HandshakeStatus.NEED_WRAP) {
            if (handshakeSink.available() == 0) {
                long[] sessionHolder = new long[1];
                int ret;
                try {
                    ret = NativeCrypto.SSL_do_handshake_bio(sslNativePointer, sessionHolder,
                            handshakeSource.getContext(), handshakeSink.getContext(), this,
                            getUseClientMode(), sslParameters.npnProtocols,
                            sslParameters.alpnProtocols);
                } catch (Exception e) {
                    throw new SSLHandshakeException(e);
                }

                if (ret == 1) {
                    try {
                        sslParameters.setupSession(sessionHolder[0], sslNativePointer, null, null,
                                getPeerPort(), true);
                    } catch (IOException e) {
                        throw new SSLHandshakeException(e);
                    }
                }
            }
            writeSinkToByteBuffer(handshakeSink, dst);
            return new SSLEngineResult(Status.OK, getHandshakeStatus(), 0, 0);
        }

        try {
            int totalRead = 0;
            byte[] buffer = null;

            for (ByteBuffer src : srcs) {
                int toRead = src.remaining();
                if (buffer == null || toRead > buffer.length) {
                    buffer = new byte[toRead];
                }
                /*
                 * We can't just use .mark() here because the caller might be
                 * using it.
                 */
                src.duplicate().get(buffer, 0, toRead);
                int numRead = NativeCrypto.SSL_write_BIO(sslNativePointer, buffer, toRead,
                        localToRemoteSink.getContext(), this);
                src.position(src.position() + numRead);
                totalRead += numRead;
            }

            return new SSLEngineResult(Status.OK, getHandshakeStatus(), totalRead,
                    writeSinkToByteBuffer(localToRemoteSink, dst));
        } catch (IOException e) {
            throw new SSLException(e);
        }
    }

    /** Writes data available in a BIO sink to a ByteBuffer. */
    private static int writeSinkToByteBuffer(OpenSSLBIOSink sink, ByteBuffer dst) {
        int toWrite = Math.min(sink.available(), dst.remaining());
        dst.put(sink.toByteArray(), sink.position(), toWrite);
        sink.skip(toWrite);
        return toWrite;
    }

    private int writeBytesToByteBuffers(byte[] buffer, int numRead, ByteBuffer[] dsts)
            throws SSLException {
        int offset = 0;
        for (int i = 0; i < dsts.length && offset < numRead; i++) {
            int toPut = Math.min(dsts[i].remaining(), numRead - offset);
            dsts[i].put(buffer, offset, toPut);
            offset += toPut;
        }
        if (offset != numRead) {
            throw new SSLException("Buffers were not large enough; still "
                    + (buffer.length - offset) + " bytes left.");
        }
        return offset;
    }

    @Override
    public void onSSLStateChange(long sslSessionNativePtr, int type, int val) {
        synchronized (stateLock) {
            switch (type) {
                case NativeCrypto.SSL_CB_HANDSHAKE_DONE:
                    if (engineState != EngineState.HANDSHAKE_STARTED) {
                        throw new IllegalStateException("Completed handshake while in mode "
                                + engineState);
                    }
                    engineState = EngineState.HANDSHAKE_COMPLETED;
                    break;
                case NativeCrypto.SSL_CB_HANDSHAKE_START:
                    // For clients, this will allow the NEED_UNWRAP status to be
                    // returned.
                    engineState = EngineState.HANDSHAKE_STARTED;
                    break;
            }
        }
    }

    @Override
    public void verifyCertificateChain(long sslSessionNativePtr, long[] certRefs,
            String authMethod) throws CertificateException {
        try {
            X509TrustManager x509tm = sslParameters.getX509TrustManager();
            if (x509tm == null) {
                throw new CertificateException("No X.509 TrustManager");
            }
            if (certRefs == null || certRefs.length == 0) {
                throw new SSLException("Peer sent no certificate");
            }
            OpenSSLX509Certificate[] peerCertChain = new OpenSSLX509Certificate[certRefs.length];
            for (int i = 0; i < certRefs.length; i++) {
                peerCertChain[i] = new OpenSSLX509Certificate(certRefs[i]);
            }

            // Used for verifyCertificateChain callback
            sslParameters.handshakeSession = new OpenSSLSessionImpl(sslSessionNativePtr, null,
                    peerCertChain, getPeerHost(), getPeerPort(), null);

            boolean client = sslParameters.getUseClientMode();
            if (client) {
                if (x509tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
                    x509etm.checkServerTrusted(peerCertChain, authMethod, this);
                } else {
                    x509tm.checkServerTrusted(peerCertChain, authMethod);
                }
            } else {
                String authType = peerCertChain[0].getPublicKey().getAlgorithm();
                if (x509tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager x509etm = (X509ExtendedTrustManager) x509tm;
                    x509etm.checkClientTrusted(peerCertChain, authType, this);
                } else {
                    x509tm.checkClientTrusted(peerCertChain, authType);
                }
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException(e);
        } finally {
            // Clear this before notifying handshake completed listeners
            sslParameters.handshakeSession = null;
        }
    }

    @Override
    public void clientCertificateRequested(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws CertificateEncodingException, SSLException {
        String[] keyTypes = new String[keyTypeBytes.length];
        for (int i = 0; i < keyTypeBytes.length; i++) {
            keyTypes[i] = SSLParametersImpl.getClientKeyType(keyTypeBytes[i]);
        }

        X500Principal[] issuers;
        if (asn1DerEncodedPrincipals == null) {
            issuers = null;
        } else {
            issuers = new X500Principal[asn1DerEncodedPrincipals.length];
            for (int i = 0; i < asn1DerEncodedPrincipals.length; i++) {
                issuers[i] = new X500Principal(asn1DerEncodedPrincipals[i]);
            }
        }
        X509KeyManager keyManager = sslParameters.getX509KeyManager();
        String alias =
                (keyManager != null) ? keyManager.chooseClientAlias(keyTypes, issuers, null) : null;
        sslParameters.setCertificate(sslNativePointer, alias);
    }

    private void free() {
        if (sslNativePointer == 0) {
            return;
        }
        NativeCrypto.SSL_free(sslNativePointer);
        sslNativePointer = 0;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            free();
        } finally {
            super.finalize();
        }
    }

    @Override
    public SSLSession getHandshakeSession() {
        return sslParameters.handshakeSession;
    }
}
