/*
 * Copyright (C) 2019 The Android Open Source Project
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

public class ConscryptLog {
    private static final String NAMESPACE = "android.net.ssl";
    public static final int TLS_HANDSHAKE_START = 0;
    public static final int TLS_CERTIFICATE_EXCEPTION = 1;

    private ConscryptLog() {}

    public static void tlsHandshakeStart(String formatString, String hostname, int port) {
        Platform.log(NAMESPACE, TLS_HANDSHAKE_START, formatString, hostname, port);
    }

    public static void tlsCertificateException(String formatString, String hostname, int port,
            java.security.cert.CertificateException e) {
        Platform.log(NAMESPACE, TLS_CERTIFICATE_EXCEPTION, formatString, hostname, port, e);
    }
}
