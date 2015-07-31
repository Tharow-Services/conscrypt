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

import junit.framework.TestCase;

import java.net.ServerSocket;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocketFactory;

import libcore.java.security.TestKeyStore;

import static org.conscrypt.TestUtils.assertEqualByteArrays;

public class OpenSSLSocketImplTest extends TestCase {
    private static final long TIMEOUT_SECONDS = 5;

    @Override
    protected void setUp() throws java.lang.Exception {
        // Generate the keys beforehand to avoid timing out in tests
        TestKeyStore.getClient();
        TestKeyStore.getServer();
    }

    interface Hooks {
        TestKeyStore getTestKeyStore();
        OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener) throws IOException;
    }

    class ClientHooks implements Hooks {
        @Override
        public TestKeyStore getTestKeyStore() {
            return TestKeyStore.getClient();
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener) throws IOException {
            OpenSSLSocketImpl socket = (OpenSSLSocketImpl)factory.createSocket(
                    listener.getInetAddress(),
                    listener.getLocalPort());
            socket.setUseClientMode(true);
            return socket;
        }
    }

    class ServerHooks implements Hooks {
        @Override
        public TestKeyStore getTestKeyStore() {
            return TestKeyStore.getServer();
        }

        @Override
        public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener) throws IOException {
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
                TestKeyStore keyStore = hooks.getTestKeyStore();

                OpenSSLContextImpl context = OpenSSLContextImpl.getPreferred();
                context.engineInit(
                    keyStore.keyManagers,
                    keyStore.trustManagers,
                    null
                );

                SSLSocketFactory factory = context.engineGetSocketFactory();
                OpenSSLSocketImpl socket = hooks.createSocket(factory, listener);

                socket.startHandshake();

                return socket;
            }
        });

        executor.shutdown();

        return future;
    }

    public void test_handshake() throws Exception {
        ServerSocket listener = new ServerSocket(0);
        Future<OpenSSLSocketImpl> clientFuture = handshake(listener, new ClientHooks());
        Future<OpenSSLSocketImpl> serverFuture =  handshake(listener, new ServerHooks());

        OpenSSLSocketImpl client = clientFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        OpenSSLSocketImpl server = serverFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    public void test_sct_extension() throws Exception {
        // This does not need to be correctly encoded SCT list
        // We only test whether is transmitted correctly
        final byte[] TESTDATA = "foobar".getBytes("UTF-8");

        ServerSocket listener = new ServerSocket(0);
        Future<OpenSSLSocketImpl> clientFuture = handshake(listener, new ClientHooks() {
            @Override
            public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener) throws IOException {
                OpenSSLSocketImpl socket = super.createSocket(factory, listener);
                socket.setSCTExtensionEnabled(true);
                return socket;
            }
        });

        Future<OpenSSLSocketImpl> serverFuture = handshake(listener, new ServerHooks() {
            @Override
            public OpenSSLSocketImpl createSocket(SSLSocketFactory factory, ServerSocket listener) throws IOException {
                OpenSSLSocketImpl socket = super.createSocket(factory, listener);
                socket.setSCTExtensionData(TESTDATA);
                return socket;
            }
        });

        OpenSSLSocketImpl client = clientFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        OpenSSLSocketImpl server = serverFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        assertEqualByteArrays(TESTDATA, client.getSCTExtensionData());
    }
}

