/*
 * Copyright 2016 The Android Open Source Project
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

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

/**
 * An SSLSession that is only valid until we have confirmed that our SSL_SESSION is correct.
 */
class OpenSSLTransientSession extends OpenSSLAbstractSession {
    private final long creationTime = System.currentTimeMillis();

    private long lastAccessedTime = creationTime;

    /** Certificates for the peer. Cached on-demand. */
    private volatile OpenSSLX509Certificate[] peerCertificates;

    /** Certificates for local. Cached on-demand. */
    private volatile OpenSSLX509Certificate[] localCertificates;

    private final OpenSSLSocketHolder socketHolder;

    public OpenSSLTransientSession(
            OpenSSLSocketHolder socketHolder, AbstractSessionContext sessionContext) {
        super(sessionContext);
        this.socketHolder = socketHolder;
    }

    @Override
    public byte[] getId() {
        return null;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    @Override
    public java.security.cert.X509Certificate[] getX509PeerCertificates()
            throws SSLPeerUnverifiedException {
        OpenSSLX509Certificate[] result = peerCertificates;
        if (result == null) {
            // single-check idiom
            peerCertificates = result = OpenSSLX509Certificate.createCertChain(
                    NativeCrypto.SSL_get_peer_cert_chain(socketHolder.getSSLSocketNativeRef()));
        }
        return result;
    }

    @Override
    protected java.security.cert.X509Certificate[] getX509LocalCertificates() {
        OpenSSLX509Certificate[] result = localCertificates;
        if (result == null) {
            // single-check idiom
            localCertificates = result = OpenSSLX509Certificate.createCertChain(
                    NativeCrypto.SSL_get_certificate(socketHolder.getSSLSocketNativeRef()));
        }
        return result;
    }

    @Override
    public String getCipherSuite() {
        return NativeCrypto.SSL_get_current_cipher(socketHolder.getSSLSocketNativeRef());
    }

    @Override
    public String getProtocol() {
        return NativeCrypto.SSL_get_version(socketHolder.getSSLSocketNativeRef());
    }

    @Override
    public String getPeerHost() {
        return socketHolder.getHostnameOrIP();
    }

    @Override
    public int getPeerPort() {
        return socketHolder.getPort();
    }

    @Override
    public String getRequestedServerName() {
        return socketHolder.getHostname();
    }

    @Override
    public List<byte[]> getStatusResponses() {
        return Collections.singletonList(
                NativeCrypto.SSL_get_ocsp_response(socketHolder.getSSLSocketNativeRef()));
    }

    @Override
    public byte[] getTlsSctData() {
        return NativeCrypto.SSL_get_signed_cert_timestamp_list(
                socketHolder.getSSLSocketNativeRef());
    }

    @Override
    public void setLastAccessedTime(long accessTimeMillis) {
        lastAccessedTime = accessTimeMillis;
    }

    @Override
    void resetId() {
        // Do nothing.
    }
}