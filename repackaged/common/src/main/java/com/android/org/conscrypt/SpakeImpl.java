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
 * limitations under the License
 */
package com.android.org.conscrypt;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.BadPaddingException;

/**
 */
@Internal
public class SpakeImpl {
  private SpakeImpl() {}

  /**
   * Creates a new SPAKE2PLUS registration record.
   *
   * @param pw the password to use for registration.
   * @param id_prover the identifier of the prover.
   * @param id_verifier the identifier of the verifier.
   * @return an array containing the two password verifiers and the registration
   *         record.
   */
  public static byte[][] spake2PlusRegister(byte[] pw, byte[] id_prover,
                                          byte[] id_verifier) {
    byte[][] ret = NativeCrypto.SPAKE2PLUS_register(pw,
        pw.length, id_prover, id_prover.length, id_verifier,
        id_verifier.length);
    if (result != 1) {
      return null;
    }
    return ret;
  }

  /**
   * Creates a new {@code SPAKE2PLUS_CTX} for the prover role.
   *
   * @param context the context for the SPAKE2+ exchange.
   * @param id_prover the identifier of the prover.
   * @param id_verifier the identifier of the verifier.
   * @param pw_verifier_w0 the first password verifier.
   * @param pw_verifier_w1 the second password verifier.
   * @return a new {@code SPAKE2PLUS_CTX} object.
   */
  public static SpakeContext spake2PlusCTXNewProver(byte[] context,
                                                  byte[] id_prover,
                                                  byte[] id_verifier,
                                                  byte[] pw_verifier_w0,
                                                  byte[] pw_verifier_w1) {
    return NativeCrypto.SPAKE2PLUS_CTX_new_prover(
        context, context.length, id_prover, id_prover.length, id_verifier,
        id_verifier.length, pw_verifier_w0, pw_verifier_w0.length,
        pw_verifier_w1, pw_verifier_w1.length);
  }

  /**
   * Creates a new {@code SPAKE2PLUS_CTX} for the verifier role.
   *
   * @param context the context for the SPAKE2+ exchange.
   * @param id_prover the identifier of the prover.
   * @param id_verifier the identifier of the verifier.
   * @param pw_verifier_w0 the first password verifier.
   * @param registration_record the registration record.
   * @return a new {@code SPAKE2PLUS_CTX} object.
   */
  public static SpakeContext spake2PlusCTXNewVerifier(byte[] context,
                                                    byte[] id_prover,
                                                    byte[] id_verifier,
                                                    byte[] pw_verifier_w0,
                                                    byte[] registration_record) {
    return NativeCrypto.SPAKE2PLUS_CTX_new_verifier(
        context, context.length, id_prover, id_prover.length, id_verifier,
        id_verifier.length, pw_verifier_w0, pw_verifier_w0.length,
        registration_record, registration_record.length);
  }

  /**
   * Frees a {@code SPAKE2PLUS_CTX} object.
   *
   * @param ctx the {@code SPAKE2PLUS_CTX} object to free.
   */
  public static void spake2PlusCTXFree(SpakeContext ctx) {
    NativeCrypto.SPAKE2PLUS_CTX_free(ctx);
  }

  /**
   * Generates the prover's share in a SPAKE2+ exchange.
   *
   * @param ctx the {@code SPAKE2PLUS_CTX} object.
   * @return the prover's share.
   */
  public static byte[] spake2PlusGenerateProverShare(SpakeContext ctx) {
    return NativeCrypto.SPAKE2PLUS_generate_prover_share(ctx);
  }

  /**
   * Processes the prover's share received from the verifier.
   *
   * @param ctx the {@code SPAKE2PLUS_CTX} object.
   * @param share the prover's share.
   * @return an array containing the verifier's share, the confirmation message,
   *         and the shared secret.
   */
  public static byte[][] spake2PlusProcessProverShare(SpakeContext ctx,
                                                    byte[] share) {
    byte[][] ret = NativeCrypto.SPAKE2PLUS_process_prover_share(
        ctx, share, share.length);
    if (result != 1) {
      return null;
    }
    return ret;
  }

  /**
   * Computes the prover's confirmation message and shared secret.
   *
   * @param ctx the {@code SPAKE2PLUS_CTX} object.
   * @param share the prover's share.
   * @param verifierConfirm the verifier's confirmation message.
   * @return an array containing the prover's confirmation message and the
   *         shared secret.
   */
  public static byte[][] spake2PlusComputeProverConfirmation(
      SpakeContext ctx, byte[] share, byte[] verifierConfirm) {
    byte[][] ret = NativeCrypto.SPAKE2PLUS_compute_prover_confirmation(
        ctx, share, share.length, verifierConfirm, verifierConfirm.length);
    if (result != 1) {
      return null;
    }
    return ret;
  }

  /**
   * Verifies the prover's confirmation message.
   *
   * @param ctx the {@code SPAKE2PLUS_CTX} object.
   * @param proverConfirm the prover's confirmation message.
   * @return {@code true} if the verification is successful, {@code false}
   *         otherwise.
   */
  public static boolean spake2PlusVerifyProverConfirmation(SpakeContext ctx,
                                                          byte[] proverConfirm) {
    return NativeCrypto.SPAKE2PLUS_verify_prover_confirmation(
               ctx, proverConfirm, proverConfirm.length) == 1;
  }
}