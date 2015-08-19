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

import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CTLogInfo {
    private final byte[] logId;
    private final PublicKey publicKey;
    private final String description;
    private final String url;

    public CTLogInfo(PublicKey publicKey, String description, String url) {
        try {
            this.logId = MessageDigest.getInstance("SHA-256")
                .digest(publicKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available
            throw new RuntimeException(e);
        }

        this.publicKey = publicKey;
        this.description = description;
        this.url = url;
    }

    public byte[] getID() {
        return logId;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getDescription() {
        return description;
    }

    public String getUrl() {
        return url;
    }
}

