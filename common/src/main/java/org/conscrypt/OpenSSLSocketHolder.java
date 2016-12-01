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

interface OpenSSLSocketHolder {
    /**
     * Returns reference to a BoringSSL "SSL*"
     */
    public long getSSLSocketNativeRef();

    /**
     * For the purposes of an SSLSession, we want a way to represent the
     * supplied hostname or the IP address in a textual representation. We do
     * not want to perform reverse DNS lookups on this address.
     */
    public String getHostnameOrIP();

    /**
     * Returns the hostname that was supplied during socket creation. No DNS
     * resolution is attempted before returning the hostname.
     */
    public String getHostname();

    /**
     * The port that has been requested to connect.
     */
    public int getPort();
}
