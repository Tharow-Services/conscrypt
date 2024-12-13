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

package com.android.org.conscrypt.metrics;

import static com.android.org.conscrypt.metrics.ConscryptStatsLog.*;

import com.android.org.conscrypt.Internal;

/**
 * Certificate Transparency Verification Reason.
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public enum CertificateTransparencyVerificationReason {
    UNKNOWN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN),
    APP_OPT_IN(CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN),
    DOMAIN_OPT_IN(
            CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN);

    final int id;

    public int getId() {
        return this.id;
    }

    private CertificateTransparencyVerificationReason(int id) {
        this.id = id;
    }
}
