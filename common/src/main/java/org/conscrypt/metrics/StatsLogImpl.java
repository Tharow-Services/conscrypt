/*
 * Copyright (C) 2020 The Android Open Source Project
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
package org.conscrypt.metrics;

import org.conscrypt.Internal;
import org.conscrypt.Platform;
import org.conscrypt.ct.LogStore;
import org.conscrypt.ct.PolicyCompliance;
import org.conscrypt.ct.VerificationResult;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Reimplement with reflection calls the logging class,
 * generated by frameworks/statsd.
 * <p>
 * In case atom is changed, generate new wrapper with stats-log-api-gen
 * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
 * newEvent() method.
 * <p>
 * $ stats-log-api-gen \
 *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
 *   --module conscrypt \
 *   --javaPackage org.conscrypt.metrics \
 *   --javaClass StatsLog
 **/
@Internal
public final class StatsLogImpl implements StatsLog {
    /**
     * TlsHandshakeReported tls_handshake_reported
     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int
     * cipher_suite, int handshake_duration_millis, int source, int[] uid);
     */
    public static final int TLS_HANDSHAKE_REPORTED = 317;

    /**
     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status,
     * int loaded_compat_version, int min_compat_version_available, int major_version, int
     * minor_version);
     */
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;

    /**
     * CertificateTransparencyVerificationReported certificate_transparency_verification_reported
     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
     * int result, int reason, int policy_compatibility_version, int
     * major_version, int minor_version, int num_cert_scts, int num_ocsp_scts,
     * int num_tls_scts);
     */
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED = 989;

    // clang-format off

    // Values for CertificateTransparencyLogListStateChanged.status
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN = 0;
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS = 1;
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND = 2;
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED = 3;
    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED = 4;

    // Values for CertificateTransparencyVerificationReported.result
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN = 0;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS = 1;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_GENERIC_FAILURE = 2;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND = 3;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT = 4;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE = 5;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT = 6;

    // Values for CertificateTransparencyVerificationReported.reason
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN = 0;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_DEVICE_WIDE_ENABLED = 1;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN = 3;
    public static final int CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN = 4;

    // clang-format on

    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r);
            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    // Ignore
                }
            });
            return thread;
        }
    });

    private static final StatsLog INSTANCE = new StatsLogImpl();
    private StatsLogImpl() {}
    public static StatsLog getInstance() {
        return INSTANCE;
    }

    @Override
    public void countTlsHandshake(
            boolean success, String protocol, String cipherSuite, long duration) {
        Protocol proto = Protocol.forName(protocol);
        CipherSuite suite = CipherSuite.forName(cipherSuite);

        write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
                Platform.getStatsSource(), Platform.getUids());
    }

    private static int logStoreStateToMetricsState(LogStore.State state) {
        switch (state) {
            case UNINITIALIZED:
            case LOADED:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
            case NOT_FOUND:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_NOT_FOUND;
            case MALFORMED:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_PARSING_FAILED;
            case COMPLIANT:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_SUCCESS;
            case NON_COMPLIANT:
                return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_EXPIRED;
        }
        return CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED__STATUS__STATUS_UNKNOWN;
    }

    @Override
    public void updateCTLogListStatusChanged(LogStore logStore) {
        int state = logStoreStateToMetricsState(logStore.getState());
        write(CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, state, logStore.getCompatVersion(),
                logStore.getMinCompatVersionAvailable(), logStore.getMajorVersion(),
                logStore.getMinorVersion());
    }

    private static int policyComplianceToMetrics(
            VerificationResult result, PolicyCompliance compliance) {
        if (compliance == PolicyCompliance.COMPLY) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_SUCCESS;
        } else if (result.getValidSCTs().size() == 0) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_NO_SCTS_FOUND;
        } else if (compliance == PolicyCompliance.NOT_ENOUGH_SCTS
                || compliance == PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS) {
            return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAILURE_SCTS_NOT_COMPLIANT;
        }
        return CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_UNKNOWN;
    }

    @Override
    public void reportCTVerificationResult(LogStore store, VerificationResult result,
            PolicyCompliance compliance, int verificationReason) {
        if (store.getState() == LogStore.State.NOT_FOUND
                || store.getState() == LogStore.State.MALFORMED) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE,
                    verificationReason, 0, 0, 0, 0, 0, 0);
        } else if (store.getState() == LogStore.State.NON_COMPLIANT) {
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED,
                    CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__RESULT__RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT,
                    verificationReason, 0, 0, 0, 0, 0, 0);
        } else if (store.getState() == LogStore.State.COMPLIANT) {
            int comp = policyComplianceToMetrics(result, compliance);
            write(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED, comp, verificationReason,
                    store.getCompatVersion(), store.getMajorVersion(), store.getMinorVersion(),
                    result.numCertSCTs(), result.numOCSPSCTs(), result.numTlsSCTs());
        }
    }

    private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
            org.conscrypt.metrics.Source source, int[] uids) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ConscryptStatsLog.write(
                        atomId, success, protocol, cipherSuite, duration, source, uids);
            }
        });
    }

    private void write(int atomId, int status, int loadedCompatVersion,
            int minCompatVersionAvailable, int majorVersion, int minorVersion) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ConscryptStatsLog.write(atomId, status, loadedCompatVersion,
                        minCompatVersionAvailable, majorVersion, minorVersion);
            }
        });
    }

    private void write(int atomId, int verificationResult, int verificationReason,
            int policyCompatVersion, int majorVersion, int minorVersion, int numEmbeddedScts,
            int numOcspScts, int numTlsScts) {
        e.execute(new Runnable() {
            @Override
            public void run() {
                ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
                builder.setAtomId(atomId);
                builder.writeInt(verificationResult);
                builder.writeInt(verificationReason);
                builder.writeInt(policyCompatVersion);
                builder.writeInt(majorVersion);
                builder.writeInt(minorVersion);
                builder.writeInt(numEmbeddedScts);
                builder.writeInt(numOcspScts);
                builder.writeInt(numTlsScts);
                builder.usePooledBuffer();
                ReflexiveStatsLog.write(builder.build());
            }
        });
    }
}
