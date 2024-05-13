/*
 * Copyright (C) 2012 The Android Open Source Project
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

package org.conscrypt;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Internal
public final class CertBlocklistImpl implements CertBlocklist {
    private static final Logger logger = Logger.getLogger(CertBlocklistImpl.class.getName());

    private final Set<BigInteger> serialBlocklist;
    private final Set<ByteString> pubkeyBlocklist;

    /**
     * public for testing only.
     */
    public CertBlocklistImpl(Set<BigInteger> serialBlocklist, Set<ByteString> pubkeyBlocklist) {
        this.serialBlocklist = serialBlocklist;
        this.pubkeyBlocklist = pubkeyBlocklist;
    }

    public static CertBlocklist getDefault() {
        String androidData = System.getenv("ANDROID_DATA");
        String blocklistRoot = androidData + "/misc/keychain/";
        String defaultPubkeyBlocklistPath = blocklistRoot + "pubkey_blacklist.txt";
        String defaultSerialBlocklistPath = blocklistRoot + "serial_blacklist.txt";

        Set<ByteString> pubkeyBlocklist = readPublicKeyBlockList(defaultPubkeyBlocklistPath);
        Set<BigInteger> serialBlocklist = readSerialBlockList(defaultSerialBlocklistPath);
        return new CertBlocklistImpl(serialBlocklist, pubkeyBlocklist);
    }

    private static boolean isHex(String value) {
        try {
            new BigInteger(value, 16);
            return true;
        } catch (NumberFormatException e) {
            logger.log(Level.WARNING, "Could not parse hex value " + value, e);
            return false;
        }
    }

    private static boolean isPubkeyHash(String value) {
        if (value.length() != 40) {
            logger.log(Level.WARNING, "Invalid pubkey hash length: " + value.length());
            return false;
        }
        return isHex(value);
    }

    private static String readBlocklist(String path) {
        try {
            return readFileAsString(path);
        } catch (FileNotFoundException ignored) {
            // Ignored
        } catch (IOException e) {
            logger.log(Level.WARNING, "Could not read blocklist", e);
        }
        return "";
    }

    // From IoUtils.readFileAsString
    private static String readFileAsString(String path) throws IOException {
        return readFileAsBytes(path).toString("UTF-8");
    }

    // Based on IoUtils.readFileAsBytes
    private static ByteArrayOutputStream readFileAsBytes(String path) throws IOException {
        RandomAccessFile f = null;
        try {
            f = new RandomAccessFile(path, "r");
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) f.length());
            byte[] buffer = new byte[8192];
            while (true) {
                int byteCount = f.read(buffer);
                if (byteCount == -1) {
                    return bytes;
                }
                bytes.write(buffer, 0, byteCount);
            }
        } finally {
            closeQuietly(f);
        }
    }

    // Base on IoUtils.closeQuietly
    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (RuntimeException rethrown) {
                throw rethrown;
            } catch (Exception ignored) {
                // Ignored
            }
        }
    }

    private static Set<BigInteger> readSerialBlockList(String path) {

        /* Start out with a base set of known bad values.
         *
         * WARNING: Do not add short serials to this list!
         *
         * Since this currently doesn't compare the serial + issuer, you
         * should only add serials that have enough entropy here. Short
         * serials may inadvertently match a certificate that was issued
         * not in compliance with the Baseline Requirements.
         */
        Set<BigInteger> bl = new HashSet<BigInteger>(Arrays.asList(
            // From http://src.chromium.org/viewvc/chrome/trunk/src/net/base/x509_certificate.cc?revision=78748&view=markup
            // Not a real certificate. For testing only.
            new BigInteger("077a59bcd53459601ca6907267a6dd1c", 16),
            new BigInteger("047ecbe9fca55f7bd09eae36e10cae1e", 16),
            new BigInteger("d8f35f4eb7872b2dab0692e315382fb0", 16),
            new BigInteger("b0b7133ed096f9b56fae91c874bd3ac0", 16),
            new BigInteger("9239d5348f40d1695a745470e1f23f43", 16),
            new BigInteger("e9028b9578e415dc1a710a2b88154447", 16),
            new BigInteger("d7558fdaf5f1105bb213282b707729a3", 16),
            new BigInteger("f5c86af36162f13a64f54f6dc9587c06", 16),
            new BigInteger("392a434f0e07df1f8aa305de34e0c229", 16),
            new BigInteger("3e75ced46b693021218830ae86a82a71", 16)
        ));

        // attempt to augment it with values taken from gservices
        String serialBlocklist = readBlocklist(path);
        if (!serialBlocklist.equals("")) {
            for (String value : serialBlocklist.split(",", -1)) {
                try {
                    bl.add(new BigInteger(value, 16));
                } catch (NumberFormatException e) {
                    logger.log(Level.WARNING, "Tried to blacklist invalid serial number " + value, e);
                }
            }
        }

        // whether that succeeds or fails, send it on its merry way
        return Collections.unmodifiableSet(bl);
    }

    private static Set<ByteString> readPublicKeyBlockList(String path) {

        // start out with a base set of known bad values
        Set<ByteString> bl = new HashSet<ByteString>();

        // Blocklist test cert for CTS. The cert and key can be found in
        // src/test/resources/blocklist_test_ca.pem and
        // src/test/resources/blocklist_test_ca_key.pem.
        bl.add(new ByteString("bae78e6bed65a2bf60ddedde7fd91e825865e93d".getBytes(UTF_8)));

        // Blocklist statically included in Conscrypt. See constants/.
        for (String staticPubKey : StaticBlocklist.PUBLIC_KEYS) {
            bl.add(new ByteString(staticPubKey.getBytes(UTF_8)));
        }

        // attempt to augment it with values taken from gservices
        String pubkeyBlocklist = readBlocklist(path);
        if (!pubkeyBlocklist.equals("")) {
            for (String value : pubkeyBlocklist.split(",", -1)) {
                value = value.trim();
                if (isPubkeyHash(value)) {
                    bl.add(new ByteString(value.getBytes(UTF_8)));
                } else {
                    logger.log(Level.WARNING, "Tried to blocklist invalid pubkey " + value);
                }
            }
        }

        return bl;
    }

    @Override
    public boolean isPublicKeyBlockListed(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, "Unable to get SHA1 MessageDigest", e);
            return false;
        }
        byte[] out = toHex(md.digest(encoded));
        for (ByteString blocklisted : pubkeyBlocklist) {
            if (Arrays.equals(blocklisted.bytes, out)) {
                return true;
            }
        }
        return false;
    }

    private static final byte[] HEX_TABLE = { (byte) '0', (byte) '1', (byte) '2', (byte) '3',
        (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a',
        (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f'};

    private static byte[] toHex(byte[] in) {
        byte[] out = new byte[in.length * 2];
        int outIndex = 0;
        for (int i = 0; i < in.length; i++) {
            int value = in[i] & 0xff;
            out[outIndex++] = HEX_TABLE[value >> 4];
            out[outIndex++] = HEX_TABLE[value & 0xf];
        }
        return out;
    }

    @Override
    public boolean isSerialNumberBlockListed(BigInteger serial) {
        return serialBlocklist.contains(serial);
    }

    private static List<ByteString> toByteStrings(byte[]... allBytes) {
        List<ByteString> byteStrings = new ArrayList<>(allBytes.length + 1);
        for (byte[] bytes : allBytes) {
            byteStrings.add(new ByteString(bytes));
        }
        return byteStrings;
    }

    private static class ByteString {
        final byte[] bytes;

        public ByteString(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }
            if (!(o instanceof ByteString)) {
                return false;
            }

            ByteString other = (ByteString) o;
            return Arrays.equals(bytes, other.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }
}
