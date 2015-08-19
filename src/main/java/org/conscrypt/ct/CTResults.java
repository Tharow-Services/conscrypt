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

import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

public class CTResults {
    private final List<SCTVerificationResult> validSCTs = new ArrayList();
    private final List<SCTVerificationResult> invalidSCTs = new ArrayList();

    public void addResult(SCTVerificationResult result) {
        if (result.status == SCTVerificationResult.Status.VALID) {
            validSCTs.add(result);
        } else {
            invalidSCTs.add(result);
        }
    }

    public List<SCTVerificationResult> getValidSCTs() {
        return Collections.unmodifiableList(validSCTs);
    }

    public List<SCTVerificationResult> getInvalidSCTs() {
        return Collections.unmodifiableList(invalidSCTs);
    }
}

