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

#include <stdio.h>
#include <string.h>

#include <string>

#include <jni.h>

constexpr bool IsX86BuildArch() {
#if defined(__i386__)
    return true;
#elif defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

constexpr bool IsArmBuildArch() {
#if defined(__arm__)
    return true;
#elif defined(__aarch64__)
    return true;
#else
    return false;
#endif
}

extern "C" jboolean Java_com_android_org_conscrypt_java_security_CpuFeatures_isNativeBridgedABI(
        JNIEnv*, jclass) {
    FILE* fp = popen("uname -m", "re");
    char buf[128];
    memset(buf, '\0', sizeof(buf));
    char* str = fgets(buf, sizeof(buf), fp);
    pclose(fp);
    if (!str) {
        // Assume no native bridge if uname didn't work.
        return static_cast<jboolean>(false);
    }

    std::string uname_string = buf;

    bool is_native_bridged_abi;
    if (IsX86BuildArch()) {
        is_native_bridged_abi = uname_string.find("86") == std::string::npos;
    } else if (IsArmBuildArch()) {
        is_native_bridged_abi = uname_string.find("arm") == std::string::npos &&
                                uname_string.find("aarch64") == std::string::npos;
    } else {
        is_native_bridged_abi = false;
    }

    return static_cast<jboolean>(is_native_bridged_abi);
}
