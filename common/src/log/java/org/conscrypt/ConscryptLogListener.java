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

import java.util.function.Supplier;
import libcore.api.CorePlatformApi;
import libcore.util.NonNull;
import libcore.util.VendorLog;

public class ConscryptLogListener implements VendorLog.Listener {
    private static final String NAMESPACE = "android.net.ssl";
    private static final int TLS_HANDSHAKE_START = 0;
    private static final int TLS_CERTIFICATE_EXCEPTION = 1;

    @Override
    public final void onMessage(
            String namespace, int entryType, Supplier<String> messageSupplier, Object... args) {
        if (!namespace.equals(NAMESPACE)) {
            return;
        }
        switch (entryType) {
            case TLS_HANDSHAKE_START: {
                String hostname = (String) args[0];
                int port = (int) args[1];
                onTlsHandshakeStart(messageSupplier, hostname, port);
                break;
            }
            case TLS_CERTIFICATE_EXCEPTION: {
                String hostname = (String) args[0];
                int port = (int) args[1];
                java.security.cert.CertificateException certificateException =
                        (java.security.cert.CertificateException) args[2];
                onTlsCertificateException(messageSupplier, hostname, port, certificateException);
                break;
            }
            default:
                // do nothing, unknown new message type; could also log to logcat
                break;
        }
    }

    @CorePlatformApi
    protected void onTlsHandshakeStart(@NonNull Supplier<@NonNull String> messageSupplier,
            @NonNull String hostname, int port) {}

    @CorePlatformApi
    protected void onTlsCertificateException(@NonNull Supplier<@NonNull String> messageSupplier,
            @NonNull String hostname, int port,
            java.security.cert.CertificateException certificateException) {}
}
