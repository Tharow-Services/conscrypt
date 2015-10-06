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

package org.conscrypt.ct;

import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLKey;
import java.security.NoSuchAlgorithmException;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.StringBufferInputStream;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Scanner;

public class CTLogStoreImpl implements CTLogStore {
    private static final File defaultUserLogDir;
    private static final File defaultSystemLogDir;
    // Lazy loaded by getKnownLog
    private static CTLogInfo[] defaultFallbackLogs = null;
    static {
        String ANDROID_DATA = System.getenv("ANDROID_DATA");
        String ANDROID_ROOT = System.getenv("ANDROID_ROOT");
        defaultUserLogDir = new File(ANDROID_DATA + "/misc/keychain/ct_known_logs/");
        defaultSystemLogDir = new File(ANDROID_ROOT + "/etc/security/ct_known_logs/");
    }

    private static File userLogDir;
    private static File systemLogDir;
    private static CTLogInfo[] fallbackLogs;

    public CTLogStoreImpl() {
        this(defaultUserLogDir, defaultSystemLogDir, getDefaultFallbackLogs());
    }

    public CTLogStoreImpl(File userLogDir, File systemLogDir, CTLogInfo[] fallbackLogs) {
        this.userLogDir = userLogDir;
        this.systemLogDir = systemLogDir;
        this.fallbackLogs = fallbackLogs;
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        String filename = hexEncode(logId);
        try {
            return loadLog(new File(systemLogDir, filename));
        } catch (FileNotFoundException e) {}

        try {
            return loadLog(new File(userLogDir, filename));
        } catch (FileNotFoundException e) {}

        for (CTLogInfo log: fallbackLogs) {
            if (Arrays.equals(logId, log.getID())) {
                return log;
            }
        }
        return null;
    }

    public static CTLogInfo[] getDefaultFallbackLogs() {
        if (defaultFallbackLogs != null) {
            return defaultFallbackLogs;
        }

        CTLogInfo logs[] = new CTLogInfo[KnownLogs.LOG_COUNT];
        for (int i = 0; i < KnownLogs.LOG_COUNT; i++) {
            try {
                PublicKey key = new OpenSSLKey(NativeCrypto.d2i_PUBKEY(KnownLogs.LOG_KEYS[i]))
                                .getPublicKey();

                logs[i] = new CTLogInfo(key,
                                        KnownLogs.LOG_DESCRIPTIONS[i],
                                        KnownLogs.LOG_URLS[i]);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        defaultFallbackLogs = logs;
        return logs;
    }

    public static CTLogInfo loadLog(File file) throws FileNotFoundException {
        return loadLog(new FileInputStream(file));
    }

    /**
     * Load a CTLogInfo from a textual representation.
     * @return CTLogInfo instance or null if the input is not formed correctly
     */
    public static CTLogInfo loadLog(InputStream input) {
        Scanner scan = new Scanner(input).useDelimiter(",");

        String description = null, url = null, key = null;
        while (scan.hasNext()) {
            String[] parts = scan.next().split(":", 2);
            if (parts.length < 2) {
                continue;
            }

            String name = parts[0];
            String value = parts[1];
            switch (name) {
                case "description": description = value; break;
                case "url": url = value; break;
                case "key": key = value; break;
            }
        }

        if (description == null || url == null || key == null) {
            return null;
        }

        PublicKey pubkey;
        try {
            pubkey = OpenSSLKey.fromPublicKeyPemInputStream(new StringBufferInputStream(
                        "-----BEGIN PUBLIC KEY-----\n" +
                        key + "\n" +
                        "-----END PUBLIC KEY-----")).getPublicKey();
        } catch (InvalidKeyException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }

        return new CTLogInfo(pubkey, description, url);
    }

    private final static char[] HEX_DIGITS = new char[] {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static String hexEncode(byte[] data) {
        StringBuffer sb = new StringBuffer(data.length * 2);
        for (byte b: data) {
            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]);
            sb.append(HEX_DIGITS[b & 0x0f]);
        }
        return sb.toString();
    }
}
