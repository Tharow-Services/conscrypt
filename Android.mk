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

local_javac_flags:=-Xmaxwarns 9999999

#
# Build for the target (device).
#

core_cppflags := -std=gnu++11 -Wall -Wextra -Werror -Wunused

jni_cpp_files := $(call all-cpp-files-under,common)
#	$(call all-cpp-files-under,common/src/jni/main/cpp/conscrypt) \
#	$(call all-c-files-under,common/src/jni/main/cpp/conscrypt) \
#	$(call all-cc-files-under,common/src/jni/main/cpp/conscrypt) \
#	$(call all-files-under,common/src/jni/main/cpp/conscrypt)
# jni_cpp_files := $(call all-files-under,$(LOCAL_PATH))
$(info $(LOCAL_PATH))
$(info *my flag* jni_cpp_files $(jni_cpp_files))


all_src_files := \
  $(call all-java-files-under,common/src/main/java) \
  $(call all-java-files-under,openjdk/src/main/java)
$(info *my flag* all_src_files $(all_src_files))


# conscrypt_constants_ccflags := \
#     -Wall -Werror -std=gnu++11

# include $(CLEAR_VARS)
# $(info *my flag* conscrypt 1)
# LOCAL_MODULE := conscrypt_generate_constants
# LOCAL_CPP_EXTENSION := cc
# LOCAL_SRC_FILES := constants/src/gen/cpp/generate_constants.cc
# LOCAL_SHARED_LIBRARIES := libcrypto-host libssl-host
# LOCAL_CXX_STL := none
# include $(BUILD_HOST_EXECUTABLE)

# TARGET_OUT_ROOT := $(OUT_DIR)/target
# TARGET_COMMON_OUT_ROOT := $(TARGET_OUT_ROOT)/common
# TARGET_OUT_COMMON_GEN := $(TARGET_COMMON_OUT_ROOT)/gen
# conscrypt_generate_constants_exe := $(LOCAL_INSTALLED_MODULE)
# conscrypt_gen_java_files := $(TARGET_OUT_COMMON_GEN)/conscrypt/NativeConstants.java

# $(conscrypt_gen_java_files): $(conscrypt_generate_constants_exe)
# 	mkdir -p $(dir $@)
# 	$< > $@

# # Create the conscrypt library
# include $(CLEAR_VARS)
# LOCAL_SRC_FILES := $(call all-java-files-under,src/main/java)
# LOCAL_SRC_FILES += $(call all-java-files-under,src/platform/java)
# LOCAL_GENERATED_SOURCES := $(conscrypt_gen_java_files)
# LOCAL_JAVA_LIBRARIES := core-oj core-libart
# LOCAL_NO_STANDARD_LIBRARIES := true
# LOCAL_JAVACFLAGS := $(local_javac_flags)
# LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
# LOCAL_MODULE_TAGS := optional
# LOCAL_MODULE := conscrypt
# LOCAL_REQUIRED_MODULES := libjavacrypto
# LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
# include $(BUILD_JAVA_LIBRARY)

# Conscrypt JNI library for host OpenJDK
# To be self-contained, this shared library statically links in all of its
# Android-specific dependencies.
include $(CLEAR_VARS)
$(info *my flag* conscrypt 0)
LOCAL_MODULE := my_lib
include $(BUILD_HOST_SHARED_LIBRARY)

# libabsl-host (host shared library)
# ========================================================
# include $(CLEAR_VARS)
# LOCAL_MODULE := libabsl-host
# LOCAL_CPP_EXTENSION := .cc
# LOCAL_CLANG := true
# LOCAL_SRC_FILES := $(libabslCommonSrc)
# LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
# LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
# include $(BUILD_HOST_SHARED_LIBRARY)

include $(CLEAR_VARS)
$(info *my flag* conscrypt 1)
$(info $(LOCAL_PATH))
LOCAL_MODULE := libconscrypt_openjdk_jni
LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE_TAGS := optional
LOCAL_CLANG := true
LOCAL_CFLAGS := -DCONSCRYPT_OPENJDK
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/common/src/jni/unbundled/include \
	$(LOCAL_PATH)/common/src/jni/main/include/ \
	$(TOP)/chromium/src/third_party/jdk/current/include/linux/ \
	$(TOP)/chromium/src/third_party/jdk/current/include/
# port openjdk to external

# LOCAL_SRC_FILES := $(call all-cpp-files-under,common/src/jni/main/cpp/conscrypt)
LOCAL_SRC_FILES := \
	common/src/jni/main/cpp/conscrypt/compatibility_close_monitor.cc\
	common/src/jni/main/cpp/conscrypt/jniload.cc\
	common/src/jni/main/cpp/conscrypt/jniutil.cc\
	common/src/jni/main/cpp/conscrypt/native_crypto.cc\
	common/src/jni/main/cpp/conscrypt/netutil.cc
LOCAL_EXPORT_STATIC_LIBRARIES := libcrypto_static # libssl_static
LOCAL_HOST_SHARED_LIBRARIES := libssl
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_SANITIZE := never
LOCAL_CXX_STL := libc++_static
LOCAL_MULTILIB := both # 64
include $(BUILD_HOST_SHARED_LIBRARY)

# # Stub library for unbundled builds
# include $(CLEAR_VARS)
# LOCAL_SRC_FILES := $(call all-java-files-under,android-stub/src/main/java)
# LOCAL_JAVACFLAGS := $(local_javac_flags)
# LOCAL_MODULE := conscrypt-stubs
# LOCAL_JACK_FLAGS := -D jack.classpath.default-libraries=false
# include $(BUILD_STATIC_JAVA_LIBRARY)

# Unbundled Conscrypt jar
include $(CLEAR_VARS)
$(info *my flag* conscrypt 2)
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
local_javac_flags :=
bundled_test_java_files :=
all_src_files :=
