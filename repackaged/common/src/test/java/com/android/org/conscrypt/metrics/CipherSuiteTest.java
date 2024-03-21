/* GENERATED SOURCE. DO NOT MODIFY. */
package com.android.org.conscrypt.metrics;

import static org.junit.Assert.assertSame;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * @hide This class is not part of the Android public SDK API
 */
@RunWith(JUnit4.class)
public class CipherSuiteTest {

    @Test
    public void consistency() {
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            assertSame(cipherSuite, CipherSuite.forName(cipherSuite.name()));
        }
        assertSame(CipherSuite.UNKNOWN_CIPHER_SUITE, CipherSuite.forName("random junk"));
    }

    @Test
    public void consistenc2() {
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            assertSame(cipherSuite, CipherSuite.forName(cipherSuite.name()));
            assertSame(CipherSuite.getId(), CipherSuite(CipherSuite.valueOf(cipherSuite.name())));
        }
        assertSame(CipherSuite.TLS_CIPHER_FAILED, CipherSuite.forName("TLS_CIPHER_FAILED"));
        assertSame(CipherSuite.TLS_CIPHER_FAILED, CipherSuite(65535));
    }
}
