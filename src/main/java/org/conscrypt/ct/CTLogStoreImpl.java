package org.conscrypt;

import org.conscrypt.ct.CTLogStore;
import org.conscrypt.ct.CTLogInfo;

import java.util.Map;
import java.util.HashMap;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;

import java.nio.ByteBuffer;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.PublicKey;

public class CTLogStoreImpl implements CTLogStore {
    final static private String PILOT_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/f\n" +
        "HTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n" +
        "-----END PUBLIC KEY-----";
    final static private String AVIATOR_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I\n" +
        "1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n" +
        "-----END PUBLIC KEY-----";
    final static private String ROCKETEER_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG\n" +
        "+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n" +
        "-----END PUBLIC KEY-----";
    final static private String DIGICERT_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+H\n" +
        "CFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n" +
        "-----END PUBLIC KEY-----";
    final static private String CERTLY_IO_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS\n" +
        "2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==\n" +
        "-----END PUBLIC KEY-----";
    final static private String IZENPE_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up\n" +
        "+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==\n" +
        "-----END PUBLIC KEY-----";
    final static private String SYMANTEC_KEY =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOm\n" +
        "kY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n" +
        "-----END PUBLIC KEY-----";

    final static private String[][] LOGS = new String[][] {
        new String[] { PILOT_KEY, "Google 'Pilot' log", "https://ct.googleapis.com/pilot/"},
        new String[] { AVIATOR_KEY, "Google 'Aviator' log", "https://ct.googleapis.com/aviator/"},
        new String[] { ROCKETEER_KEY, "Google 'Rocketeer' log", "https://ct.googleapis.com/rocketeer/"},
        new String[] { DIGICERT_KEY, "DigiCert Log Server", "https://ct1.digicert-ct.com/log/"},
        new String[] { CERTLY_IO_KEY, "Certly.IO log", "https://log.certly.io/"},
        new String[] { IZENPE_KEY, "Izenpe log", "https://ct.izenpe.com/"},
        new String[] { SYMANTEC_KEY, "Symantec log", "https://ct.ws.symantec.com/"}
    };

    final static private Map<ByteBuffer, CTLogInfo> KNOWN_LOGS = new HashMap();
    static {
        for (String[] log: LOGS) {
            try {
                PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(
                    new ByteArrayInputStream(log[0].getBytes(Charset.defaultCharset()))
                ).getPublicKey();
                CTLogInfo logInfo = new CTLogInfo(key, log[1], log[2]);
                KNOWN_LOGS.put(ByteBuffer.wrap(logInfo.getID()), logInfo);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public CTLogInfo getKnownLog(byte[] logId) {
        return KNOWN_LOGS.get(ByteBuffer.wrap(logId));
    }
}
