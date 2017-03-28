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

/* This file is generated by print_log_list.py
 * https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py */

package org.conscrypt.ct;

import org.conscrypt.Internal;

/**
 * @hide
 */
@Internal
public final class KnownLogs {
    public static final int LOG_COUNT = 8;
    public static final String[] LOG_DESCRIPTIONS = new String[] {
        "Google 'Pilot' log",
        "Google 'Aviator' log",
        "DigiCert Log Server",
        "Google 'Rocketeer' log",
        "Certly.IO log",
        "Izenpe log",
        "Symantec log",
        "Venafi log",
    };
    public static final String[] LOG_URLS = new String[] {
        "ct.googleapis.com/pilot",
        "ct.googleapis.com/aviator",
        "ct1.digicert-ct.com/log",
        "ct.googleapis.com/rocketeer",
        "log.certly.io",
        "ct.izenpe.com",
        "ct.ws.symantec.com",
        "ctlog.api.venafi.com",
    };
    public static final byte[][] LOG_KEYS = new byte[][] {
        // Google 'Pilot' log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, 125, -88, 75, 18, 41, -128, -93, 61, -83,
            -45, 90, 119, -72, -52, -30, -120, -77, -91, -3, -15, -45, 12, -51, 24,
            12, -24, 65, 70, -24, -127, 1, 27, 21, -31, 75, -15, 27, 98, -35, 54, 10,
            8, 24, -70, -19, 11, 53, -124, -48, -98, 64, 60, 45, -98, -101, -126,
            101, -67, 31, 4, 16, 65, 76, -96
        },
        // Google 'Aviator' log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, -41, -12, -52, 105, -78, -28, 14, -112,
            -93, -118, -22, 90, 112, 9, 79, -17, 19, 98, -48, -115, 73, 96, -1, 27,
            64, 80, 7, 12, 109, 113, -122, -38, 37, 73, -115, 101, -31, 8, 13, 71,
            52, 107, -67, 39, -68, -106, 33, 62, 52, -11, -121, 118, 49, -79, 127,
            29, -55, -123, 59, 13, -9, 31, 63, -23
        },
        // DigiCert Log Server
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, 2, 70, -59, -66, 27, -69, -126, 64, 22,
            -24, -63, -46, -84, 25, 105, 19, 89, -8, -8, 112, -123, 70, 64, -71, 56,
            -80, 35, -126, -88, 100, 76, 127, -65, -69, 52, -97, 74, 95, 40, -118,
            -49, 25, -60, 0, -10, 54, 6, -109, 101, -19, 76, -11, -87, 33, 98, 90,
            -40, -111, -21, 56, 36, 64, -84, -24
        },
        // Google 'Rocketeer' log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, 32, 91, 24, -56, 60, -63, -117, -77, 49,
            8, 0, -65, -96, -112, 87, 43, -73, 71, -116, 111, -75, 104, -80, -114,
            -112, 120, -23, -96, 115, -22, 79, 40, 33, 46, -100, -64, -12, 22, 27,
            -86, -7, -43, -41, -87, -128, -61, 78, 47, 82, 60, -104, 1, 37, 70, 36,
            37, 40, 35, 119, 45, 5, -62, 64, 122
        },
        // Certly.IO log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, 11, 35, -53, -123, 98, -104, 97, 72, 4,
            115, -21, 84, 93, -13, -48, 7, -116, 45, 25, 45, -116, 54, -11, -21,
            -113, 1, 66, 10, 124, -104, 38, 39, -63, -75, -35, -110, -109, -80, -82,
            -8, -101, 61, 12, -40, 76, 78, 29, -7, 21, -5, 71, 104, 123, -70, 102,
            -73, 37, -100, -48, 74, -62, 102, -37, 72
        },
        // Izenpe log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, 39, 100, 57, 12, 45, -36, 80, 24, -8, 33,
            0, -94, 14, -19, 44, -22, 62, 117, -70, -97, -109, 100, 9, 0, 17, -60,
            17, 23, -85, 92, -49, 15, 116, -84, -75, -105, -112, -109, 0, 91, -72,
            -21, -9, 39, 61, -39, -78, 10, -127, 95, 47, 13, 117, 56, -108, 55, -103,
            30, -10, 7, 118, -32, -18, -66
        },
        // Symantec log
        new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72,
            -50, 61, 3, 1, 7, 3, 66, 0, 4, -106, -22, -84, 28, 70, 12, 27, 85, -36,
            13, -4, -75, -108, 39, 70, 87, 66, 112, 58, 105, 24, -30, -65, 59, -60,
            -37, -85, -96, -12, -74, 108, -64, 83, 63, 77, 66, 16, 51, -16, 88, -105,
            -113, 107, -66, 114, -12, 42, -20, 28, 66, -86, 3, 47, 26, 126, 40, 53,
            118, -103, 8, 61, 33, 20, -122
        },
        // Venafi log
        new byte[] {
            48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0,
            3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -94, 90, 72, 31,
            23, 82, -107, 53, -53, -93, 91, 58, 31, 83, -126, 118, -108, -93, -1,
            -128, -14, 28, 55, 60, -64, -79, -67, -63, 89, -117, -85, 45, 101, -109,
            -41, -13, -32, 4, -43, -102, 111, -65, -42, 35, 118, 54, 79, 35, -103,
            -53, 84, 40, -83, -116, 21, 75, 101, 89, 118, 65, 74, -100, -90, -9, -77,
            59, 126, -79, -91, 73, -92, 23, 81, 108, -128, -36, 42, -112, 80, 75,
            -120, 36, -23, -91, 18, 50, -109, 4, 72, -112, 2, -6, 95, 14, 48, -121,
            -114, 85, 118, 5, -18, 42, 76, -50, -93, 106, 105, 9, 110, 37, -83, -126,
            118, 15, -124, -110, -6, 56, -42, -122, 78, 36, -113, -101, -80, 114,
            -53, -98, -30, 107, 63, -31, 109, -55, 37, 117, 35, -120, -95, 24, 88, 6,
            35, 51, 120, -38, 0, -48, 56, -111, 103, -46, -90, 125, 39, -105, 103,
            90, -63, -13, 47, 23, -26, -22, -46, 91, -24, -127, -51, -3, -110, 104,
            -25, -13, 6, -16, -23, 114, -124, -18, 1, -91, -79, -40, 51, -38, -50,
            -125, -91, -37, -57, -49, -42, 22, 126, -112, 117, 24, -65, 22, -36, 50,
            59, 109, -115, -85, -126, 23, 31, -119, 32, -115, 29, -102, -26, 77, 35,
            8, -33, 120, 111, -58, 5, -65, 95, -82, -108, -105, -37, 95, 100, -44,
            -18, 22, -117, -93, -124, 108, 113, 43, -15, -85, 127, 93, 13, 50, -18,
            4, -30, -112, -20, 65, -97, -5, 57, -63, 2, 3, 1, 0, 1
        },
    };
}
