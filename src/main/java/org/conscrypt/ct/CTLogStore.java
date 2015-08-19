package org.conscrypt.ct;

public interface CTLogStore {
    CTLogInfo getKnownLog(byte[] logId);
}

