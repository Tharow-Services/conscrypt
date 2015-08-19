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

import org.conscrypt.OpenSSLKey;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class CTLogStoreImpl implements CTLogStore {
    // Use an inner class to avoid loading the keys if they aren't needed
    private static class KnownLogs {
        private static final String PILOT_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/f\n" +
            "HTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n" +
            "-----END PUBLIC KEY-----";
        private static final String AVIATOR_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I\n" +
            "1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n" +
            "-----END PUBLIC KEY-----";
        private static final String ROCKETEER_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG\n" +
            "+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n" +
            "-----END PUBLIC KEY-----";
        private static final String DIGICERT_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+H\n" +
            "CFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n" +
            "-----END PUBLIC KEY-----";
        private static final String CERTLY_IO_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS\n" +
            "2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==\n" +
            "-----END PUBLIC KEY-----";
        private static final String IZENPE_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up\n" +
            "+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==\n" +
            "-----END PUBLIC KEY-----";
        private static final String SYMANTEC_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOm\n" +
            "kY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n" +
            "-----END PUBLIC KEY-----";
        private static final String VENAFI_KEY = 
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OC\n" +
            "dpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym\n" +
            "97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWt\n" +
            "gnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB\n" +
            "8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauC\n" +
            "Fx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5\n" +
            "wQIDAQAB\n" +
            "-----END PUBLIC KEY-----";

        private static final CTLogInfo[] DEFAULT_KNOWN_LOGS;
        static {
            String[][] logs = new String[][] {
                new String[] { PILOT_KEY, "Google 'Pilot' log", "https://ct.googleapis.com/pilot/"},
                new String[] { AVIATOR_KEY, "Google 'Aviator' log", "https://ct.googleapis.com/aviator/"},
                new String[] { ROCKETEER_KEY, "Google 'Rocketeer' log", "https://ct.googleapis.com/rocketeer/"},
                new String[] { DIGICERT_KEY, "DigiCert Log Server", "https://ct1.digicert-ct.com/log/"},
                new String[] { CERTLY_IO_KEY, "Certly.IO log", "https://log.certly.io/"},
                new String[] { IZENPE_KEY, "Izenpe log", "https://ct.izenpe.com/"},
                new String[] { SYMANTEC_KEY, "Symantec log", "https://ct.ws.symantec.com/"},
                new String[] { VENAFI_KEY, "Venafi", "https://ctlog.api.venafi.com/"},
            };

            DEFAULT_KNOWN_LOGS = new CTLogInfo[logs.length];
            for (int i = 0; i < logs.length; i++) {
                try {
                    PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(
                        new ByteArrayInputStream(logs[i][0].getBytes(Charset.forName("UTF-8")))
                    ).getPublicKey();
                    DEFAULT_KNOWN_LOGS[i] = new CTLogInfo(key, logs[i][1], logs[i][2]);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    private CTLogInfo[] knownLogs;
    public CTLogStoreImpl() {
        // Lazy loaded by getKnownLog
        knownLogs = null;
    }

    public CTLogStoreImpl(CTLogInfo[] knownLogs) {
        this.knownLogs = knownLogs;
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        if (knownLogs == null) {
            knownLogs = KnownLogs.DEFAULT_KNOWN_LOGS;
        }
        for (CTLogInfo log: knownLogs) {
            if (Arrays.equals(logId, log.getID())) {
                return log;
            }
        }
        return null;
    }
}
