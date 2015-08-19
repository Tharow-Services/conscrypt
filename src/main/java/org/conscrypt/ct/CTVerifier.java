/*
 * Copyright (C) 2015 The Android Open Source Project
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

package org.conscrypt.ct;

import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLX509Certificate;

import java.util.Set;
import java.util.HashSet;
import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;

public class CTVerifier {
    private final CTLogStore store;

    public CTVerifier(CTLogStore store) {
        this.store = store;
    }

    /**
     * Verify a certificate chain for transparency.
     * Signed timestamps are extracted from the leaf certificate, TLS extension, and stapled ocsp
     * response, and verified against the list of known logs.
     * @throws IllegalArgumentException if the chain is empty
     */
    public CTResults verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain,
            byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
        List<SignedCertificateTimestamp> scts = new ArrayList();

        if (chain.length == 0) {
            throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
        }
        
        if (tlsData != null) {
            List<SignedCertificateTimestamp> tlsScts = getSCTsFromTLSExtension(tlsData);
            if (tlsScts != null) {
                scts.addAll(tlsScts);
            }
        }

        if (ocspData != null) {
            List<SignedCertificateTimestamp> ocspScts = getSCTsFromOCSPResponse(ocspData, chain);
            if (ocspScts != null) {
                scts.addAll(ocspScts);
            }
        }

        List<SignedCertificateTimestamp> embeddedScts = getSCTsFromX509Extension(chain[0]);
        if (embeddedScts != null) {
            scts.addAll(embeddedScts);
        }

        return verifySCTs(chain, scts);
    }

    private CTResults verifySCTs(OpenSSLX509Certificate[] chain, List<SignedCertificateTimestamp> scts)
            throws CertificateEncodingException {
        CTResults results = new CTResults();

        OpenSSLX509Certificate leaf = chain[0];
        CertificateEntry certEntry = CertificateEntry.createForX509Certificate(leaf);

        CertificateEntry precertEntry = null;
        if (chain.length >= 2) {
            OpenSSLX509Certificate issuer = chain[1];
            OpenSSLX509Certificate preCert = leaf.withDeletedExtension(CTConstants.X509_SCT_LIST_OID);
            precertEntry = CertificateEntry.createForPrecertificate(preCert, issuer);
        }

        for (SignedCertificateTimestamp sct: scts) {
            CertificateEntry entry = null;
            switch (sct.getOrigin()) {
                case EMBEDDED:
                    if (precertEntry == null) {
                        results.addResult(new SCTVerificationResult(
                                    sct, SCTVerificationResult.Status.OTHER, null));
                    }
                    entry = precertEntry;
                    break;
                case TLS_EXTENSION:
                case OCSP_RESPONSE:
                    entry = certEntry;
                    break;
            }

            results.addResult(verifySingleSCT(sct, entry));
        }

        return results;
    }

    private SCTVerificationResult verifySingleSCT(SignedCertificateTimestamp sct,
                                                  CertificateEntry entry) {
        CTLogInfo log = store.getKnownLog(sct.getLogID());
        if (log == null) {
            return new SCTVerificationResult(sct, SCTVerificationResult.Status.UNKNOWN_LOG, null);
        }

        String algorithm = sct.getSignature().getAlgorithm();

        try {
            byte[] toVerify = sct.encodeTBS(entry);
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(log.getPublicKey());
            signature.update(toVerify);
            if (!signature.verify(sct.getSignature().getSignature())) {
                return new SCTVerificationResult(sct, SCTVerificationResult.Status.BAD_SIGNATURE, log);
            }
            return new SCTVerificationResult(sct, SCTVerificationResult.Status.VALID, log);
        } catch (SerializationException e) {
            return new SCTVerificationResult(sct, SCTVerificationResult.Status.OTHER, log);
        } catch (NoSuchAlgorithmException e) {
            return new SCTVerificationResult(sct, SCTVerificationResult.Status.OTHER, log);
        } catch (InvalidKeyException e) {
            return new SCTVerificationResult(sct, SCTVerificationResult.Status.OTHER, log);
        } catch (SignatureException e) {
            // This shouldn't happen, since we initialize Signature correctly.
            throw new RuntimeException(e);
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromSCTList(byte[] data,
            SignedCertificateTimestamp.Origin origin) throws SerializationException {
        List<SignedCertificateTimestamp> scts = new ArrayList();

        byte[][] sctList = Serialization.readList(data, 2, 2);

        for (byte[] encodedSCT: sctList) {
            try  {
                SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(encodedSCT, origin);
                scts.add(sct);
            } catch (SerializationException e) {
                // Ignore errors
            }
        }

        return scts;
    }

    private List<SignedCertificateTimestamp> getSCTsFromTLSExtension(byte[] data) {
        try {
            return getSCTsFromSCTList(data, SignedCertificateTimestamp.Origin.TLS_EXTENSION);
        } catch (SerializationException e) {
            return null;
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(byte[] data,
            OpenSSLX509Certificate[] chain) {
        if (chain.length < 2) {
            return null;
        }

        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, CTConstants.OCSP_SCT_LIST_OID,
                                                                chain[0].getContext(),
                                                                chain[1].getContext());
        if (extData == null) {
            return null;
        }

        try {
            return getSCTsFromSCTList(
                    Serialization.readDEROctetString(
                      Serialization.readDEROctetString(extData)),
                    SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
        } catch (SerializationException e) {
            return null;
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromX509Extension(OpenSSLX509Certificate leaf) {
        byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
        if (extData == null) {
            return null;
        }

        try {
            return getSCTsFromSCTList(
                    Serialization.readDEROctetString(
                      Serialization.readDEROctetString(extData)),
                    SignedCertificateTimestamp.Origin.EMBEDDED);
        } catch (SerializationException e) {
            return null;
        }
    }
}

