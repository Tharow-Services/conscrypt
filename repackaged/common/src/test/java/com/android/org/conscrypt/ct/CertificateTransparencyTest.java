/* GENERATED SOURCE. DO NOT MODIFY. */
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

package com.android.org.conscrypt.ct;

import static com.android.org.conscrypt.TestUtils.openTestFile;
import static com.android.org.conscrypt.TestUtils.readTestFile;

import static org.junit.Assert.assertEquals;

import com.android.org.conscrypt.OpenSSLX509Certificate;
import com.android.org.conscrypt.TestUtils;
import com.android.org.conscrypt.metrics.NoopStatsLog;
import com.android.org.conscrypt.metrics.StatsLog;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class CertificateTransparencyTest {
    class NoPlatformCertificateTransparency extends CertificateTransparency {
        public NoPlatformCertificateTransparency(
                LogStore logStore, Policy policy, Verifier verifier, StatsLog statsLog) {
            super(logStore, policy, verifier, statsLog);
        }

        public boolean isCTVerificationRequired(String host) {
            return true;
        }
        public int reasonCTVerificationRequired(String host) {
            return 0;
        }
    }

    class MockStatsLog extends NoopStatsLog {
        int numCalled = 0;

        @Override
        public void reportCTVerificationResult(LogStore logStore, VerificationResult result,
                PolicyCompliance compliance, int VerificationReason) {
            numCalled++;
        }
    }

    private LogInfo log;
    private LogStore store;
    private Verifier verifier;
    private Policy alwaysCompliantStorePolicy;

    @Before
    public void setUp() throws Exception {
        alwaysCompliantStorePolicy = new Policy() {
            @Override
            public boolean isLogStoreCompliant(LogStore store) {
                return true;
            }
            @Override
            public PolicyCompliance doesResultConformToPolicy(
                    VerificationResult result, X509Certificate leaf) {
                return PolicyCompliance.COMPLY;
            }
        };
        PublicKey key = TestUtils.readPublicKeyPemFile("ct-server-key-public.pem");
        log = new LogInfo.Builder()
                      .setPublicKey(key)
                      .setDescription("Test Log")
                      .setUrl("http://example.com")
                      .setOperator("LogOperator")
                      .setState(LogInfo.STATE_USABLE, 1643709600000L)
                      .build();
        store = new LogStore() {
            @Override
            public State getState() {
                return LogStore.State.COMPLIANT;
            }

            @Override
            public long getTimestamp() {
                return 0;
            }

            @Override
            public int getMajorVersion() {
                return 1;
            }

            @Override
            public int getMinorVersion() {
                return 2;
            }

            @Override
            public int getCompatVersion() {
                return 1;
            }

            @Override
            public int getMinCompatVersionAvailable() {
                return 1;
            }

            @Override
            public LogInfo getKnownLog(byte[] logId) {
                if (Arrays.equals(logId, log.getID())) {
                    return log;
                } else {
                    return null;
                }
            }
        };

        verifier = new Verifier(store);
    }

    @Test
    public void testCheckCT() throws Exception {
        MockStatsLog statsLog = new MockStatsLog();
        NoPlatformCertificateTransparency subSys = new NoPlatformCertificateTransparency(
                store, alwaysCompliantStorePolicy, verifier, statsLog);
        OpenSSLX509Certificate certEmbedded =
                OpenSSLX509Certificate.fromX509PemInputStream(openTestFile("cert-ct-embedded.pem"));

        List<X509Certificate> chain = Arrays.asList(certEmbedded);
        subSys.checkCT(chain, null, null, "android.com");
        assertEquals(1, statsLog.numCalled);
    }
}
