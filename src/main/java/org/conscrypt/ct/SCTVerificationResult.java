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

/**
 * Verification result for a single SCT.
 */
public final class SCTVerificationResult {
    public enum Status {
        VALID,
        BAD_SIGNATURE,
        UNKNOWN_LOG,
        OTHER
    }

    public final SignedCertificateTimestamp sct;
    public final Status status;

    // May be null if status is UNKNOWN_LOG or OTHER
    public final CTLogInfo log;

    /**
     * @throws IllegalArgumentException if log is null and status is VALID or BAD_SIGNATURE
     */
    public SCTVerificationResult(SignedCertificateTimestamp sct, Status status, CTLogInfo log) {
        if ((status == Status.VALID || status == Status.BAD_SIGNATURE) &&
                log == null) {
            throw new IllegalArgumentException(
                    "Status VALID or BAD_SIGNATURE requires log information");
        }
        this.sct = sct;
        this.status = status;
        this.log = log;
    }
}

