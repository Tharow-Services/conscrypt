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

import org.conscrypt.OpenSSLKey;
import junit.framework.TestCase;
import java.io.StringBufferInputStream;
import java.io.PrintWriter;
import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.PublicKey;

import static org.conscrypt.TestUtils.openTestFile;

public class CTLogStoreImplTest extends TestCase {
    private static final String[] LOG_KEYS = new String[] {
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmXg8sUUzwBYaWrRb+V0IopzQ6o3U" +
        "yEJ04r5ZrRXGdpYM8K+hB0pXrGRLI0eeWz+3skXrS0IO83AhA3GpRL6s6w==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErEULmlBnX9L/+AK20hLYzPMFozYx" +
        "pP0Wm1ylqGkPEwuDKn9DSpNSOym49SN77BLGuAXu9twOW/qT+ddIYVBEIw==",

        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP6PGcXmjlyCBz2ZFUuUjrgbZLaEF" +
        "gfLUkt2cEqlSbb4vTuB6WWmgC9h0L6PN6JF0CPcajpBKGlTI15242a8d4g=="
    };
    private static final String[] LOG_FILENAMES = new String[] {
        "df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d764",
        "84f8ae3f613b13407a75fa2893b93ab03b18d86c455fe7c241ae020033216446",
        "89baa01a445100009d8f9a238947115b30702275aafee675a7d94b6b09287619"
    };

    private static final CTLogInfo[] LOGS;
    private static final String[] LOGS_SERIALIZED;

    static {
        try {
            int logCount = LOG_KEYS.length;
            LOGS = new CTLogInfo[logCount];
            LOGS_SERIALIZED = new String[logCount];
            for (int i = 0; i < logCount; i++) {
                PublicKey key = OpenSSLKey.fromPublicKeyPemInputStream(new StringBufferInputStream(
                    "-----BEGIN PUBLIC KEY-----\n" +
                    LOG_KEYS[i] + "\n" +
                    "-----END PUBLIC KEY-----\n")).getPublicKey();
                String description = String.format("Test Log %d", i);
                String url = String.format("log%d.example.com", i);
                LOGS[i] = new CTLogInfo(key, description, url);
                LOGS_SERIALIZED[i] = String.format("description:%s,url:%s,key:%s",
                    description, url, LOG_KEYS[i]);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* CTLogStoreImpl loads the list of logs lazily when they are first needed
     * to avoid any overhead when CT is disabled.
     * This test simply forces the logs to be loaded to make sure it doesn't
     * fail, as all of the other tests use a different log store.
     */
    public void test_getDefaultFallbackLogs() {
        CTLogInfo[] knownLogs = CTLogStoreImpl.getDefaultFallbackLogs();
        assertEquals(KnownLogs.LOG_COUNT, knownLogs.length);
    }

    public void test_loadLog() throws Exception {
        CTLogInfo log = CTLogStoreImpl.loadLog(new StringBufferInputStream(LOGS_SERIALIZED[0]));
        assertEquals(LOGS[0], log);

        File testFile = writeFile(LOGS_SERIALIZED[0]);
        log = CTLogStoreImpl.loadLog(testFile);
        assertEquals(LOGS[0], log);

        // Empty log file, used to mask fallback logs
        assertEquals(null, CTLogStoreImpl.loadLog(new StringBufferInputStream("")));
        try {
            CTLogStoreImpl.loadLog(new StringBufferInputStream("randomgarbage"));
            fail("InvalidLogFileException not thrown");
        } catch (CTLogStoreImpl.InvalidLogFileException e) {}

        try {
            CTLogStoreImpl.loadLog(new File("/nonexistent"));
            fail("FileNotFoundException not thrown");
        } catch (FileNotFoundException e) {}
    }

    public void test_getKnownLog() throws Exception {
        File userDir = createTempDirectory();
        userDir.deleteOnExit();

        File systemDir = createTempDirectory();
        systemDir.deleteOnExit();

        CTLogInfo[] fallback = new CTLogInfo[] { LOGS[2] };

        CTLogStore store = new CTLogStoreImpl(userDir, systemDir, fallback);

        // Logs 0 and 1 are not present yet, so looking them up should fail
        assertEquals(null, store.getKnownLog(LOGS[0].getID()));
        assertEquals(null, store.getKnownLog(LOGS[1].getID()));
        assertEquals(LOGS[2], store.getKnownLog(LOGS[2].getID()));

        // Add logs 0 and 1 to the user and system directories respectively
        writeFile(new File(userDir, LOG_FILENAMES[0]), LOGS_SERIALIZED[0]);
        writeFile(new File(systemDir, LOG_FILENAMES[1]), LOGS_SERIALIZED[1]);

        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
        assertEquals(LOGS[1], store.getKnownLog(LOGS[1].getID()));
        assertEquals(LOGS[2], store.getKnownLog(LOGS[2].getID()));

        // Mask logs 1 and 2 by adding an empty file in the user directory
        writeFile(new File(userDir, LOG_FILENAMES[1]), "");
        writeFile(new File(userDir, LOG_FILENAMES[2]), "");

        assertEquals(LOGS[0], store.getKnownLog(LOGS[0].getID()));
        assertEquals(null, store.getKnownLog(LOGS[1].getID()));
        assertEquals(null, store.getKnownLog(LOGS[2].getID()));
    }

    /**
     * Create a temporary file and write to it.
     * The file will be deleted on exit.
     * @param contents The data to be written to the file
     * @return A reference to the temporary file
     */
    private File writeFile(String contents) throws IOException {
        File file = File.createTempFile("test", null);
        file.deleteOnExit();
        writeFile(file, contents);
        return file;
    }

    private static void writeFile(File file, String contents) throws FileNotFoundException {
        PrintWriter writer = new PrintWriter(file);
        try {
            writer.write(contents);
        } finally {
            writer.close();
        }
    }

    /*
     * This is NOT safe, as another process could create a file between delete() and mkdir()
     * It should be fine for tests though
     */
    private static File createTempDirectory() throws IOException {
        File folder = File.createTempFile("test", "");
        folder.delete();
        folder.mkdir();
        return folder;
    }
}

