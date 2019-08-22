/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <openssl/crypto.h>

int main(int, char**) {
    // If we get here, then libcrypto is either in FIPS mode (in which case
    // it doesn't run the self test), or the self test has passed. If the
    // self test ran and failed, then libcrypto will already have abort()ed.
    if (!FIPS_mode()) {
        // TODO
        /*
        // Because libcrypto isn't in FIPS mode, the self test will not have run,
        // so the device should refuse to boot. Rebooting to bootloader to wait for
        // further action from the user.
        LOG(INFO) << "libcrypto is not in FIPS mode - rebooting into bootloader";

        int result = android_reboot(ANDROID_RB_RESTART2, 0,
                                    "bootloader,boringssl-self-check-failed");
        if (result != 0) {
             LOG(ERROR) << "Failed to reboot into bootloader";
        }
        */
        return 1;
    }
    return 0;  // success
}
