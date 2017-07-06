/* Copyright (C) 2015 The Android Open Source Project
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
 * limitations under the License. */

/* This program generates output that is expected to become
 * NativeConstants.java. This reifies several OpenSSL constants into Java. */

#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/aead.h>

static const char kCopyright[] =
    "/* Copyright (C) 2015 The Android Open Source Project\n"
    " *\n"
    " * Licensed under the Apache License, Version 2.0 (the \"License\");\n"
    " * you may not use this file except in compliance with the License.\n"
    " * You may obtain a copy of the License at\n"
    " *\n"
    " *      http://www.apache.org/licenses/LICENSE-2.0\n"
    " *\n"
    " * Unless required by applicable law or agreed to in writing, software\n"
    " * distributed under the License is distributed on an \"AS IS\" BASIS,\n"
    " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or "
    "implied.\n"
    " * See the License for the specific language governing permissions and\n"
    " * limitations under the License. */\n";

int main(int /* argc */, char ** /* argv */) {
  printf("%s\n", kCopyright);
  printf("/* This file was generated by generate_constants.cc. */\n\n");
  printf("package org.conscrypt;\n\n");
  printf("final class NativeConstants {\n");

#define CONST(x) \
  printf("    static final int %s = %ld;\n", #x, (long int)(x))

  CONST(EXFLAG_CA);
  CONST(EXFLAG_CRITICAL);

  CONST(EVP_PKEY_RSA);
  CONST(EVP_PKEY_EC);

  CONST(RSA_PKCS1_PADDING);
  CONST(RSA_NO_PADDING);
  CONST(RSA_PKCS1_OAEP_PADDING);
  CONST(RSA_PKCS1_PSS_PADDING);

  CONST(SSL_MODE_SEND_FALLBACK_SCSV);
  CONST(SSL_MODE_CBC_RECORD_SPLITTING);
  CONST(SSL_MODE_ENABLE_FALSE_START);

  CONST(SSL_OP_CIPHER_SERVER_PREFERENCE);
  CONST(SSL_OP_NO_TICKET);
  CONST(SSL_OP_NO_SSLv3);
  CONST(SSL_OP_NO_TLSv1);
  CONST(SSL_OP_NO_TLSv1_1);
  CONST(SSL_OP_NO_TLSv1_2);

  CONST(SSL_ERROR_NONE);
  CONST(SSL_ERROR_WANT_READ);
  CONST(SSL_ERROR_WANT_WRITE);
  CONST(SSL_ERROR_ZERO_RETURN);

  CONST(SSL_SENT_SHUTDOWN);
  CONST(SSL_RECEIVED_SHUTDOWN);

  CONST(TLS_CT_RSA_SIGN);
  CONST(TLS_CT_ECDSA_SIGN);

  CONST(SSL_VERIFY_NONE);
  CONST(SSL_VERIFY_PEER);
  CONST(SSL_VERIFY_FAIL_IF_NO_PEER_CERT);

  CONST(SSL_CB_HANDSHAKE_START);
  CONST(SSL_CB_HANDSHAKE_DONE);

  CONST(SSL3_RT_MAX_PLAIN_LENGTH);
  CONST(SSL3_RT_MAX_PACKET_SIZE);
  CONST(SSL3_RT_CHANGE_CIPHER_SPEC);
  CONST(SSL3_RT_ALERT);
  CONST(SSL3_RT_HANDSHAKE);
  CONST(SSL3_RT_APPLICATION_DATA);
  CONST(SSL3_RT_HEADER_LENGTH);
#undef CONST

  printf("}\n");

  return 0;
}
