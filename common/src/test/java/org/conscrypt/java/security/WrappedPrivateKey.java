/*
 * Copyright (C) 2020 The Android Open Source Project
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

import java.security.PrivateKey;

class WrappedPrivateKey implements PrivateKey {
  private PrivateKey key;
  private String format;

  WrappedPrivateKey(PrivateKey key) {
    this(key, key.getFormat());
  }

  WrappedPrivateKey(PrivateKey key, String format) {
    this.key = key;
    this.format = format;
  }

  @Override
  public String getAlgorithm() {
    return key.getAlgorithm();
  }

  @Override
  public byte[] getEncoded() {
    return key.getEncoded();
  }

  @Override
  public String getFormat() {
    return format;
  }
}