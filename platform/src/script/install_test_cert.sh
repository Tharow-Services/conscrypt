#! /bin/sh
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

die() {
    echo "$@"
    exit 1
}

test "$ANDROID_BUILD_TOP" || die "Lunch first"
test "$ANDROID_SERIAL" || die "Set ANDROID_SERIAL"

VOGAR=`which vogar`
test "$VOGAR" || die "Build vogar"

TESTFILE="/system/script.tst.file"
adb shell touch "$TESTFILE" || die "Unable to write to /system"
adb shell rm "$TESTFILE" || die "Unable to remove test file(!)"

SCRIPT_DIR="$ANDROID_BUILD_TOP/external/conscrypt/platform/src/script"

FLAG_FILE="/system/etc/security/DISABLE_APEX_CERTS"
CERT_SRC="$SCRIPT_DIR/ca_for_testing.pem"
CERT_DST="/system/etc/security/cacerts/ca_for_testing.pem"
JAVA_SRC="$SCRIPT_DIR/ListTestCerts.java"

test -f "$CERT_SRC" || die "Test certificate not found"
test -f "$JAVA_SRC" || die "Java source missing"

adb shell rm -f "$FLAG_FILE" "$CERT_DST"


count_certs() {
    "$VOGAR" --mode app_process "$JAVA_SRC" | grep 'CN=Conscrypt' | wc -l
}

echo "Counting test certs before making changes"
FOUND=`count_certs`
test "$FOUND" = "0" || die "Remove all test certificates and start again"

adb shell touch "$FLAG_FILE" || die "Unable to create flag file"
adb push "$CERT_SRC" "$CERT_DST" || die "Unable to install test cert"
adb shell stop || die "Stop failed"
adb shell start || die "Start failed"

echo "Counting test certs after making changes"
FOUND=`count_certs`
test "$FOUND" = "1" || die "Test certificate not found"

echo "Success"
