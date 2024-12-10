/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.net.ssl;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;


@RunWith(JUnit4.class)
public class SpakeTest {

  @Test
  public void testSpake() {
    byte[] client_id;
    byte[] server_id;
    byte[] password;
    byte[] context;
    Socket plainSocket;

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SPAKE2+");
    tmf.init(null);

    SpakeClientKeyManagerParameters kmfParams = new SpakeClientKeyManagerParameters.Builder()
        .setClientIdentity(client_id)
        .setServerIdentity(server_id)
        .setClientPassword(password)
        .setPakeContext(context)
        .build();

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SPAKE2+");
    kmf.init(kmfParams);

    SSLContext context = SSLContext.getInstance("TlsV1.3");
    context.init(kmf.getKeyManagers(), tmf.getTrustMananagers, null);

    SocketFactory sf = context.getSocketFactory();

    SSLSocket sslSocket = sf.createSocket(plainSocket, host, port, true);
    sslSocket.startHandshake();

    byte[] server_id;
    byte[] client1_id;
    byte[] password1;
    byte[] client2_id;
    byte[] password2;
    byte[] context;
    Socket plainSocket;


    var tmf = TrustManagerFactory.getInstance("SPAKE2+");
    tmf.init(null);

    var kmfParams = new SpakeServerKeyManagerParameters.Builder()
        .addPasswordMapping(client1_id, server_id, password1)
        .addPasswordMapping(client2_id, server_id, password2)
        .setPakeContext(context)
        .build();

    var kmf = KeyManagerFactory.getInstance("SPAKE2+");
    kmf.init(kmfParams);

    var context = SSLContext.getInstance("TlsV1.3");
    context.init(kmf.getKeyManagers(), tmf.getTrustMananagers, null);

    var sf = context.getSocketFactory();

    SSLSocket sslSocket = sf.createSocket(plainSocket, host, port, true);
    sslSocket.setUseClientMode(false);
    sslSocket.startHandshake();

  }
}