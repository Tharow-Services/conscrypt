/* GENERATED SOURCE. DO NOT MODIFY. */
/*
 * Copyright (C) 2010 The Android Open Source Project
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

package com.android.org.conscrypt;

import static com.android.org.conscrypt.Platform.wrapEngine;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * OpenSSL-backed SSLContext service provider interface.
 *
 * <p>Public to allow contruction via the provider framework.
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public abstract class OpenSSLContextImpl extends SSLContextSpi {
    /**
     * The default SSLContextImpl for use with
     * SSLContext.getInstance("Default"). Protected by the
     * DefaultSSLContextImpl.class monitor.
     */
    private static DefaultSSLContextImpl defaultSslContextImpl;

    /** TLS protocols to enable by default. */
    private final String[] protocols;

    /** Client session cache. */
    private final ClientSessionContext clientSessionContext;

    /** Server session cache. */
    private final ServerSessionContext serverSessionContext;

    SSLParametersImpl sslParameters;

    /** Allows outside callers to get the preferred SSLContext. */
    @android.compat.annotation.UnsupportedAppUsage
    static OpenSSLContextImpl getPreferred() {
        return new TLSv13();
    }

    OpenSSLContextImpl(String[] protocols) {
        this.protocols = protocols;
        clientSessionContext = new ClientSessionContext();
        serverSessionContext = new ServerSessionContext();
    }

    // BEGIN Android-added: Restore missing constructor that is used by apps
    @android.compat.annotation.UnsupportedAppUsage
    private OpenSSLContextImpl() throws GeneralSecurityException, IOException {
        this(NativeCrypto.TLSV13_PROTOCOLS, true);
    }
    // END Android-added: Restore missing constructor that is used by apps

    /**
     * Constructor for the DefaultSSLContextImpl.  The unused boolean parameter is solely to
     * indicate that this constructor is desired.
     */
    @SuppressWarnings("StaticAssignmentInConstructor")
    OpenSSLContextImpl(String[] protocols, boolean unused)
            throws GeneralSecurityException, IOException {
        // TODO(prb): It looks like nowadays we can push the synchronisation into
        // DefaultSSLContextImpl itself, but put it in its own CL for safety.
        synchronized (DefaultSSLContextImpl.class) {
            this.protocols = null;
            // This is the only place defaultSslContextImpl is read or written so all
            // access is actually synchronized.
            if (defaultSslContextImpl == null) {
                clientSessionContext = new ClientSessionContext();
                serverSessionContext = new ServerSessionContext();
                defaultSslContextImpl = (DefaultSSLContextImpl) this;
            } else {
                clientSessionContext =
                        (ClientSessionContext)
                                defaultSslContextImpl.engineGetClientSessionContext();
                serverSessionContext =
                        (ServerSessionContext)
                                defaultSslContextImpl.engineGetServerSessionContext();
            }
            sslParameters = new SSLParametersImpl(defaultSslContextImpl.getKeyManagers(),
                    defaultSslContextImpl.getTrustManagers(), null, clientSessionContext,
                    serverSessionContext, protocols);
        }
    }

    /**
     * Initializes this {@code SSLContext} instance. All of the arguments are
     * optional, and the security providers will be searched for the required
     * implementations of the needed algorithms.
     *
     * @param kms the key sources or {@code null}
     * @param tms the trust decision sources or {@code null}
     * @param sr the randomness source or {@code null}
     * @throws KeyManagementException if initializing this instance fails
     */
    @Override
    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr)
            throws KeyManagementException {
        sslParameters = new SSLParametersImpl(
                kms, tms, sr, clientSessionContext, serverSessionContext, protocols);
    }

    @Override
    public SSLSocketFactory engineGetSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        return Platform.wrapSocketFactoryIfNeeded(new OpenSSLSocketFactoryImpl(sslParameters));
    }

    @Override
    public SSLServerSocketFactory engineGetServerSocketFactory() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        return new OpenSSLServerSocketFactoryImpl(sslParameters);
    }

    @Override
    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParametersImpl p = (SSLParametersImpl) sslParameters.clone();
        p.setUseClientMode(false);
        return wrapEngine(new ConscryptEngine(host, port, p));
    }

    @Override
    public SSLEngine engineCreateSSLEngine() {
        if (sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParametersImpl p = (SSLParametersImpl) sslParameters.clone();
        p.setUseClientMode(false);
        return wrapEngine(new ConscryptEngine(p));
    }

    @Override
    public SSLSessionContext engineGetServerSessionContext() {
        return serverSessionContext;
    }

    @Override
    public SSLSessionContext engineGetClientSessionContext() {
        return clientSessionContext;
    }

    /**
     * Public to allow construction via the provider framework.
     * @hide This class is not part of the Android public SDK API
     */
    public static final class TLSv13 extends OpenSSLContextImpl {
        public TLSv13() {
            super(NativeCrypto.TLSV13_PROTOCOLS);
        }
    }

    /**
     * Public to allow construction via the provider framework.
     * @hide This class is not part of the Android public SDK API
     */
    public static final class TLSv12 extends OpenSSLContextImpl {
        @android.compat.annotation.UnsupportedAppUsage
        public TLSv12() {
            super(NativeCrypto.TLSV12_PROTOCOLS);
        }
    }

    /**
     * Public to allow construction via the provider framework.
     * @hide This class is not part of the Android public SDK API
     */
    public static final class TLSv11 extends OpenSSLContextImpl {
        public TLSv11() {
            super(NativeCrypto.TLSV11_PROTOCOLS);
        }
    }

    /**
     * Public to allow construction via the provider framework.
     * @hide This class is not part of the Android public SDK API
     */
    public static final class TLSv1 extends OpenSSLContextImpl {
        public TLSv1() {
            super(NativeCrypto.TLSV1_PROTOCOLS);
        }
    }
}
