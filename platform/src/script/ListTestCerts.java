/*
 * Copyright (C) 2023 The Android Open Source Project
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
 * limitations under the License
 */

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class ListTestCerts {

  public static void main(String[] args) throws Exception {
    KeyStore ks = KeyStore.getInstance("AndroidCAStore");
    ks.load(null);

    Enumeration<String> aliases = ks.aliases();

    int count = 0;
    while (aliases.hasMoreElements()) {
      String next = aliases.nextElement();
      X509Certificate cert = (X509Certificate) ks.getCertificate(next);
      String name = cert.getSubjectX500Principal().getName();
      if (name.contains("Conscrypt")) {
        System.out.println(name);
        count++;
      }
    }
    System.out.printf("Found %d matching certs\n", count);
  }
}
