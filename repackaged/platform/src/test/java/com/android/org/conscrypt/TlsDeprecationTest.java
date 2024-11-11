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

package com.android.org.conscrypt;

import libcore.junit.util.SwitchTargetSdkVersionRule;
import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;

import javax.net.ssl.SSLSocket;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import org.junit.Rule;

/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class TlsDeprecationTest {
    @Rule
    public final TestRule switchTargetSdkVersionRule = SwitchTargetSdkVersionRule.getInstance();

    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
    @Test
    public void test34() {
        assertEquals(TestUtils.getTargetSdkVersion(), 34);
    }

    @SwitchTargetSdkVersionRule.TargetSdkVersion(35)
    @Test
    public void test35() {
        assertEquals(TestUtils.getTargetSdkVersion(), 35);
    }
}