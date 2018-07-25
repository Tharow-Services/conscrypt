/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt.java.security;

import static org.junit.Assert.assertNotNull;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import org.junit.Test;

public abstract class AbstractAlgorithmParameterGeneratorTest {

    private final String algorithmName;
    private final TestHelper<AlgorithmParameters> helper;

    protected AbstractAlgorithmParameterGeneratorTest(String algorithmName, TestHelper<AlgorithmParameters> helper) {
        this.algorithmName = algorithmName;
        this.helper = helper;
    }

    @Test
    public void testAlgorithmParameterGenerator() throws Exception {
        AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance(algorithmName);
        generator.init(1024);

        AlgorithmParameters parameters = generator.generateParameters();
        assertNotNull("generated parameters are null", parameters);
        helper.test(parameters);
    }
}
