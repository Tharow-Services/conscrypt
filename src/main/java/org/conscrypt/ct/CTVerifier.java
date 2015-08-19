package org.conscrypt.ct;

import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLX509Certificate;

import java.util.Set;
import java.util.HashSet;
import java.util.Collections;

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
     * @throws CTVerificationException if no valid timestamps are found.
     */
    public Set<CTLogInfo> verifyCertificateTransparency(OpenSSLX509Certificate[] chain,
            byte[] tlsData, byte[] ocspData) throws CTVerificationException {
        Set<CTLogInfo> validLogs = new HashSet();

        if (chain.length == 0) {
            throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
        }

        validLogs.addAll(verifySCTsFromEmbeddedX509Extension(chain));

        if (tlsData != null) {
            validLogs.addAll(verifySCTsFromTLSExtension(chain, tlsData));
        }

        if (ocspData != null) {
            validLogs.addAll(verifySCTsFromOCSPResponse(chain, ocspData));
        }

        // TODO(lietar): custom / configurable policy
        if (validLogs.isEmpty()) {
            throw new CTVerificationException("No valid SCT present.");
        }

        return validLogs;
    }

    private Set<CTLogInfo> verifySCTsFromTLSExtension(OpenSSLX509Certificate[] chain,
                                                     byte[] tlsData) {
        try {
            LogEntry certEntry = LogEntry.createForX509Certificate(chain[0]);
            return verifySCTList(certEntry, tlsData);
        } catch (CertificateEncodingException e) {
        }

        return Collections.EMPTY_SET;
    }

    private Set<CTLogInfo> verifySCTsFromEmbeddedX509Extension(OpenSSLX509Certificate[] chain) {
        try {
            if (chain.length >= 2) {
                byte[] embeddedSCTs = getSCTListFromX509Certificate(chain[0]);
                if (embeddedSCTs != null) {
                    LogEntry precertEntry = LogEntry.createForPrecertificate(chain[0], chain[1]);
                    return verifySCTList(precertEntry, embeddedSCTs);
                }
            }
        } catch (CertificateEncodingException e) {
        }

        return Collections.EMPTY_SET;
    }

    private Set<CTLogInfo> verifySCTsFromOCSPResponse(OpenSSLX509Certificate[] chain,
                                                     byte[] ocspData) {
        try {
            if (chain.length >= 2) {
                byte[] sctsFromOCSP = getSCTListFromOCSPResponse(chain[0], chain[1], ocspData);
                if (sctsFromOCSP != null) {
                    LogEntry certEntry = LogEntry.createForX509Certificate(chain[0]);
                    return verifySCTList(certEntry, sctsFromOCSP);
                }
            }
        } catch (CertificateEncodingException e) {
        }

        return Collections.EMPTY_SET;
    }

    private Set<CTLogInfo> verifySCTList(LogEntry logEntry, byte[] encodedSCTList) {
        Set<CTLogInfo> out = new HashSet();

        try {
            byte[][] sctList = SerializationUtils.readList(encodedSCTList, 2, 2);

            for (byte[] encodedSCT: sctList) {
                try  {
                    SignedCertificateTimestamp sct = SignedCertificateTimestamp.decode(encodedSCT);
                    CTLogInfo log = verifySCT(logEntry, sct);
                    out.add(log);
                } catch (SerializationException e) {
                    // Ignore errors
                } catch (InvalidTimestampException e) {
                }
            }
        } catch (SerializationException e) {
            // Ignore errors
        }

        return out;
    }

    private CTLogInfo verifySCT(LogEntry logEntry, SignedCertificateTimestamp sct)
            throws InvalidTimestampException {
        try {
            CTLogInfo log = store.getKnownLog(sct.getLogID());
            if (log == null) {
                throw new InvalidTimestampException("Unknown log");
            }

            String algorithm = sct.getSignature().getAlgorithm();

            byte[] toVerify = sct.encodeTBS(logEntry);
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(log.getPublicKey());
            signature.update(toVerify);
            if (!signature.verify(sct.getSignature().getSignature())) {
                throw new InvalidTimestampException("Signature mismatch");
            }
            return log;
        } catch (SerializationException e) {
            throw new InvalidTimestampException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidTimestampException(e);
        } catch (InvalidKeyException e) {
            throw new InvalidTimestampException(e);
        } catch (SignatureException e) {
            // This shouldn't happen, since we initialize Signature correctly.
            throw new RuntimeException(e);
        }
    }

    private byte[] getSCTListFromOCSPResponse(OpenSSLX509Certificate leaf,
            OpenSSLX509Certificate issuer, byte[] data) {
        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, CTConstants.OCSP_SCT_LIST_OID,
                                                                leaf.getContext(),
                                                                issuer.getContext());
        if (extData == null) {
            return null;
        }

        try {
            return SerializationUtils.readDEROctetString(
                    SerializationUtils.readDEROctetString(extData));
        } catch (SerializationException e) {
            return null;
        }
    }

    private byte[] getSCTListFromX509Certificate(X509Certificate leaf) {
        byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
        if (extData == null) {
            return null;
        }

        try {
            return SerializationUtils.readDEROctetString(
                    SerializationUtils.readDEROctetString(extData));
        } catch (SerializationException e) {
            return null;
        }
    }
}

