/*
 * Copyright (C) 2015 The Android Open Source Project
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

import org.conscrypt.ct.CTLogInfo;
import org.conscrypt.ct.CTLogStore;
import org.conscrypt.ct.CTLogStoreImpl;
import org.conscrypt.ct.CTVerifier;

import junit.framework.TestCase;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLHandshakeException;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readTestFile;

public class OpenSSLSocketImplTest extends TestCase {
    private static final long TIMEOUT_SECONDS = 5;

    private static final X509Certificate CA;
    private static final X509Certificate CERT;
    private static final X509Certificate CERT_EMBEDDED;
    private static final PrivateKey CERT_KEY;
    private static final CTVerifier CT_VERIFIER;

    private static final Field CONTEXT_SSL_PARAMETERS;
    static {
        try {
            CA = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("ca-cert.pem"));
            CERT = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert.pem"));
            CERT_EMBEDDED = OpenSSLX509Certificate.fromX509PemInputStream(
                    openTestFile("cert-ct-embedded.pem"));
            CERT_KEY = OpenSSLKey.fromPrivateKeyPemInputStream(
                    openTestFile("cert-key.pem")).getPrivateKey();

            PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(
                    openTestFile("ct-server-key-public.pem")).getPublicKey();
            CTLogStore store = new CTLogStoreImpl(new CTLogInfo[] {
                new CTLogInfo(key, "Test Log", "foo")
            });
            CT_VERIFIER = new CTVerifier(store);

            CONTEXT_SSL_PARAMETERS = OpenSSLContextImpl.class.getDeclaredField("sslParameters");
            CONTEXT_SSL_PARAMETERS.setAccessible(true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    abstract class Hooks implements HandshakeCompletedListener {
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        abstract OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
            throws IOException;

        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = OpenSSLContextImpl.getPreferred();
            context.engineInit(
                keyManagers,
                trustManagers,
                null
            );
            return context;
        }

        boolean isHandshakeCompleted = false;
        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            isHandshakeCompleted = true;
        }
    }

    class ClientHooks extends Hooks {
        CTVerifier ctVerifier;
        boolean ctVerificationEnabled;

        @Override
        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = super.createContext();
            SSLParametersImpl sslParameters = (SSLParametersImpl)CONTEXT_SSL_PARAMETERS.get(context);
            if (ctVerifier != null) {
                sslParameters.setCTVerifier(ctVerifier);
            }
            sslParameters.setCTVerificationEnabled(ctVerificationEnabled);
            return context;
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                throws IOException {
            OpenSSLSocketImpl socket = (OpenSSLSocketImpl)factory.createSocket(
                    listener.getInetAddress(),
                    listener.getLocalPort());
            socket.setUseClientMode(true);

            return socket;
        }
    }

    class ServerHooks extends Hooks {
        byte[] sctTLSExtension;
        byte[] ocspResponse;

        @Override
        public OpenSSLContextImpl createContext() throws Exception {
            OpenSSLContextImpl context = super.createContext();
            SSLParametersImpl sslParameters = (SSLParametersImpl)CONTEXT_SSL_PARAMETERS.get(context);
            sslParameters.setSCTExtension(sctTLSExtension);
            sslParameters.setOCSPResponse(ocspResponse);
            return context;
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener)
                throws IOException {
            OpenSSLSocketImpl socket = (OpenSSLSocketImpl)factory.createSocket(
                    listener.accept(),
                    null, -1, // hostname, port
                    true); // autoclose
            socket.setUseClientMode(false);
            return socket;
        }
    }

    Future<OpenSSLSocketImpl> handshake(final ServerSocket listener, final Hooks hooks) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<OpenSSLSocketImpl> future = executor.submit(
        new Callable<OpenSSLSocketImpl>() {
            @Override
            public OpenSSLSocketImpl call() throws Exception {
                OpenSSLContextImpl context = hooks.createContext();
                SSLSocketFactory factory = context.engineGetSocketFactory();
                OpenSSLSocketImpl socket = hooks.createSocket(factory, listener);
                socket.addHandshakeCompletedListener(hooks);

                socket.startHandshake();

                return socket;
            }
        });

        executor.shutdown();

        return future;
    }

    void doHandshake(ClientHooks clientHooks, ServerHooks serverHooks) throws Exception {
        ServerSocket listener = new ServerSocket(0);
        Future<OpenSSLSocketImpl> clientFuture = handshake(listener, clientHooks);
        Future<OpenSSLSocketImpl> serverFuture = handshake(listener, serverHooks);

        OpenSSLSocketImpl client = clientFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        OpenSSLSocketImpl server = serverFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private static void setCertificates(ClientHooks cHooks, ServerHooks sHooks,
                                        X509Certificate[] chain, PrivateKey key) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("default", key, null, chain);
        ks.setCertificateEntry("CA", chain[chain.length -1]);

        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] tms = tmf.getTrustManagers();

        KeyManagerFactory kmf =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, null);
        KeyManager[] kms = kmf.getKeyManagers();

        cHooks.trustManagers = tms;
        sHooks.keyManagers = kms;
        sHooks.trustManagers = tms;
    }

    public void test_handshake() throws Exception {
        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT, CA }, CERT_KEY);

        doHandshake(clientHooks, serverHooks);

        assertTrue(clientHooks.isHandshakeCompleted);
        assertTrue(serverHooks.isHandshakeCompleted);
    }

    public void test_handshakeWithEmbeddedSCT() throws Exception {
        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT_EMBEDDED, CA }, CERT_KEY);

        clientHooks.ctVerifier = CT_VERIFIER;
        clientHooks.ctVerificationEnabled = true;

        doHandshake(clientHooks, serverHooks);

        assertTrue(clientHooks.isHandshakeCompleted);
        assertTrue(serverHooks.isHandshakeCompleted);
    }

    public void test_handshakeWithSCTFromOCSPResponse() throws Exception {
        // This is only implemented for BoringSSL >= 201509
        if (!NativeCrypto.isBoringSSL || !NativeCrypto.isBoringSSL201509()) {
            return;
        }

        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT, CA }, CERT_KEY);

        clientHooks.ctVerifier = CT_VERIFIER;
        clientHooks.ctVerificationEnabled = true;
        serverHooks.ocspResponse = readTestFile("ocsp-response.der");

        doHandshake(clientHooks, serverHooks);

        assertTrue(clientHooks.isHandshakeCompleted);
        assertTrue(serverHooks.isHandshakeCompleted);
    }

    public void test_handshakeWithSCTFromTLSExtension() throws Exception {
        // This is only implemented for BoringSSL >= 201509
        if (!NativeCrypto.isBoringSSL || !NativeCrypto.isBoringSSL201509()) {
            return;
        }

        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT, CA }, CERT_KEY);

        clientHooks.ctVerifier = CT_VERIFIER;
        clientHooks.ctVerificationEnabled = true;
        serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list");

        doHandshake(clientHooks, serverHooks);

        assertTrue(clientHooks.isHandshakeCompleted);
        assertTrue(serverHooks.isHandshakeCompleted);
    }

    public void test_handshake_failsWithMissingSCT() throws Exception {
        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT, CA }, CERT_KEY);

        clientHooks.ctVerifier = CT_VERIFIER;
        clientHooks.ctVerificationEnabled = true;

        try {
            doHandshake(clientHooks, serverHooks);
            fail("SSLHandshakeException not thrown");
        } catch (ExecutionException e) {
            assertEquals(SSLHandshakeException.class, e.getCause().getClass());
            assertEquals(CertificateException.class, e.getCause().getCause().getClass());
        }
    }

    public void test_handshake_failsWithInvalidSCT() throws Exception {
        ServerSocket listener = new ServerSocket(0);

        ClientHooks clientHooks = new ClientHooks();
        ServerHooks serverHooks = new ServerHooks();
        setCertificates(clientHooks, serverHooks, new X509Certificate[] { CERT, CA }, CERT_KEY);

        clientHooks.ctVerifier = CT_VERIFIER;
        clientHooks.ctVerificationEnabled = true;
        serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list-invalid");

        try {
            doHandshake(clientHooks, serverHooks);
            fail("SSLHandshakeException not thrown");
        } catch (ExecutionException e) {
            assertEquals(SSLHandshakeException.class, e.getCause().getClass());
            assertEquals(CertificateException.class, e.getCause().getCause().getClass());
        }
    }
}

