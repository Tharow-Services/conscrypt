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
 * Maps statsd constants to more succinct names to be used by Conscrypt.
 * @hide This class is not part of the Android public SDK API
 */
@Internal
public final class Constants {
    public static final int SOURCE_UNKNOWN = TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_UNKNOWN;
    public static final int SOURCE_MAINLINE = TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_MAINLINE;
    public static final int SOURCE_GMS = TLS_HANDSHAKE_REPORTED__SOURCE__SOURCE_GMS;

    public static final int CERTIFICATE_TRANSPARENCY_REASON_UNKNOWN =
            ConscryptStatsLog
                    .CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_UNKNOWN;
    public static final int CERTIFICATE_TRANSPARENCY_REASON_APP_OPT_IN =
            ConscryptStatsLog
                    .CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_APP_OPT_IN;
    public static final int CERTIFICATE_TRANSPARENCY_REASON_DOMAIN_OPT_IN =
            ConscryptStatsLog
                    .CERTIFICATE_TRANSPARENCY_VERIFICATION_REPORTED__REASON__REASON_NSCONFIG_DOMAIN_OPT_IN;
}
