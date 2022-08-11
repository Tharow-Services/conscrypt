# -*- mode: makefile -*-
# Copyright (C) 2013 The Android Open Source Project
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
# limitations under the License.

#
# Definitions for building the Conscrypt Java library, native code,
# and associated tests.
#

#
# Common definitions for host and target.
#

# Conscrypt is divided into modules.
#
# The structure is:
#
#   constants/
#       src/gen             # Generates NativeConstants.java.
#   common/
#       src/main/java       # Common Java source for all platforms.
#       src/jni/
#            main           # Common C++ source for all platforms.
#            unbundled      # C++ source used for OpenJDK and unbundled Android.
#   android/
#       src/main/java       # Java source for unbundled Android.
#   openjdk/
#       src/main/java       # Java source for OpenJDK.
#       src/test
#            java/          # Java source for common tests.
#            resources/     # Support files for tests
#   platform/
#       src/main/java       # Java source for bundled Android.
#       src/test
#            java/          # Java source for bundled tests.
#
# All subdirectories are optional (hence the "2> /dev/null"s below).

LOCAL_PATH := $(call my-dir)

libconscrypt_openjdk_jni_ldlibs += \
	-Wl,--no-as-needed\
	-ldl\
	-Wl,-Bsymbolic \
	-Wl,--as-needed \
	-Wl,-z,noexecstack \
	-Wl,--warn-common \
	-pthread

libconscrypt_openjdk_jni_cpp_flags := \
	-Wall \
	-Werror \
	-std=c++14

libconscrypt_openjdk_jni_c_flags := \
	-Wall \
	-Werror \
	-DBORINGSSL_ANDROID_SYSTEM \
	-DBORINGSSL_SHARED_LIBRARY \
	-DBORINGSSL_IMPLEMENTATION \
	-DCONSCRYPT_OPENJDK \
	-DOPENSSL_SMALL \
	-D_XOPEN_SOURCE=700 \
	-Wno-unused-parameter \
	-Wno-ignored-qualifiers \
	-Wno-deprecated-copy

#
# Build for the target (device).
#

core_cppflags := -std=gnu++11 -Wall -Wextra -Werror -Wunused

all_src_files := \
  $(call all-java-files-under,common/src/main/java) \
  $(call all-java-files-under,openjdk/src/main/java)

include $(CLEAR_VARS)
LOCAL_MODULE := libconscrypt_openjdk_jni
LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE_TAGS := optional
LOCAL_CLANG := true
LOCAL_LDLIBS += $(libconscrypt_openjdk_jni_ldlibs)
LOCAL_CPPFLAGS := $(libconscrypt_openjdk_jni_cpp_flags)
LOCAL_CFLAGS := $(libconscrypt_openjdk_jni_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/common/jni/
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/common/src/jni/unbundled/include \
	$(LOCAL_PATH)/common/src/jni/main/include/ \
	$(TOP)/external/libnativehelper/include_jni/ \

LOCAL_SRC_FILES := \
	common/src/jni/main/cpp/conscrypt/compatibility_close_monitor.cc\
	common/src/jni/main/cpp/conscrypt/jniload.cc \
	common/src/jni/main/cpp/conscrypt/jniutil.cc \
	common/src/jni/main/cpp/conscrypt/netutil.cc \
	common/src/jni/main/cpp/conscrypt/native_crypto.cc

LOCAL_JAVA_LIBRARIES := jni_headers
LOCAL_STATIC_LIBRARIES := libssl_1010107f_static-host libcrypto_1010107f_static-host
LOCAL_SANITIZE := never
LOCAL_CXX_STL := libc++_static
LOCAL_MULTILIB := both # 64
include $(BUILD_HOST_SHARED_LIBRARY)

# Unbundled Conscrypt jar
include $(CLEAR_VARS)
LOCAL_MODULE := conscrypt-unbundled
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(all_src_files) constants/NativeConstants.java
# LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
# LOCAL_JAVA_LIBRARIES := conscrypt-stubs
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVACFLAGS += -XDignore.symbol.file
LOCAL_JAVA_LANGUAGE_VERSION := 1.8
java9_or_greater := $(shell test $(javac_major_version) -ge 9 && echo true)
ifeq ($(java9_or_greater),true)
  # --add-exports flag is only allowed on java9 or greater.
  # TODO(b/162131149) This is just a workaround. We should remove usage of
  # this internal package and use bouncycastle instead.
  LOCAL_JAVACFLAGS += --add-exports java.base/sun.security.pkcs=ALL-UNNAMED \
    --add-exports java.base/sun.security.x509=ALL-UNNAMED
endif
include $(BUILD_HOST_JAVA_LIBRARY)

# clear out local variables
bundled_test_java_files :=
all_src_files :=
