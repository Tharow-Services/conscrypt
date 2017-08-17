/*
 * Copyright (C) 2009 The Android Open Source Project
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

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * Supports SSL session caches.
 */
abstract class AbstractSessionContext implements SSLSessionContext {

    /**
     * Maximum lifetime of a session (in seconds) after which it's considered invalid and should not
     * be used to for new connections.
     */
    private static final int DEFAULT_SESSION_TIMEOUT_SECONDS = 8 * 60 * 60;

    private volatile int maximumSize;
    private volatile int timeout = DEFAULT_SESSION_TIMEOUT_SECONDS;

    final long sslCtxNativePointer = NativeCrypto.SSL_CTX_new();

    @SuppressWarnings("serial")
    private final Map<ByteArray, SslSessionWrapper> sessions =
            new LinkedHashMap<ByteArray, SslSessionWrapper>() {
                @Override
                protected boolean removeEldestEntry(
                        Map.Entry<ByteArray, SslSessionWrapper> eldest) {
                    // NOTE: does not take into account any session that may have become
                    // invalid.
                    if (maximumSize > 0 && size() > maximumSize) {
                        // Let the subclass know.
                        onBeforeRemoveSession(eldest.getValue());
                        return true;
                    }
                    return false;
                }
            };

    /**
     * Constructs a new session context.
     *
     * @param maximumSize of cache
     */
    AbstractSessionContext(int maximumSize) {
        this.maximumSize = maximumSize;
    }

    /**
     * This method is provided for API-compatibility only, not intended for use. No guarantees
     * are made WRT performance.
     */
    @Override
    public final Enumeration<byte[]> getIds() {
        // Make a copy of the IDs.
        final Iterator<SslSessionWrapper> iter;
        synchronized (sessions) {
            iter = Arrays.asList(sessions.values().toArray(new SslSessionWrapper[sessions.size()]))
                    .iterator();
        }
        return new Enumeration<byte[]>() {
            private SslSessionWrapper next;

            @Override
            public boolean hasMoreElements() {
                if (next != null) {
                    return true;
                }
                while (iter.hasNext()) {
                    SslSessionWrapper session = iter.next();
                    if (session.isValid()) {
                        next = session;
                        return true;
                    }
                }
                next = null;
                return false;
            }

            @Override
            public byte[] nextElement() {
                if (hasMoreElements()) {
                    byte[] id = next.getId();
                    next = null;
                    return id;
                }
                throw new NoSuchElementException();
            }
        };
    }

    /**
     * This is provided for API-compatibility only, not intended for use. No guarantees are
     * made WRT performance or the validity of the returned session.
     */
    @Override
    public final SSLSession getSession(byte[] sessionId) {
        if (sessionId == null) {
            throw new NullPointerException("sessionId");
        }
        ByteArray key = new ByteArray(sessionId);
        SslSessionWrapper session;
        synchronized (sessions) {
            session = sessions.get(key);
        }
        if (session != null && session.isValid()) {
            return session.toSSLSession();
        }
        return null;
    }

    @Override
    public final int getSessionCacheSize() {
        return maximumSize;
    }

    @Override
    public final int getSessionTimeout() {
        return timeout;
    }

    @Override
    public final void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }

        synchronized (sessions) {
            // Set the timeout on this context.
            timeout = seconds;
            // setSessionTimeout(0) is defined to remove the timeout, but passing 0
            // to SSL_CTX_set_timeout in BoringSSL sets it to the default timeout instead.
            // Pass INT_MAX seconds (68 years), since that's equivalent for practical purposes.
            if (seconds > 0) {
                NativeCrypto.SSL_CTX_set_timeout(sslCtxNativePointer, seconds);
            } else {
                NativeCrypto.SSL_CTX_set_timeout(sslCtxNativePointer, Integer.MAX_VALUE);
            }

            Iterator<SslSessionWrapper> i = sessions.values().iterator();
            while (i.hasNext()) {
                SslSessionWrapper session = i.next();
                // SSLSession's know their context and consult the
                // timeout as part of their validity condition.
                if (!session.isValid()) {
                    // Let the subclass know.
                    onBeforeRemoveSession(session);
                    i.remove();
                }
            }
        }
    }

    @Override
    public final void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("size < 0");
        }

        int oldMaximum = maximumSize;
        maximumSize = size;

        // Trim cache to size if necessary.
        if (size < oldMaximum) {
            trimToSize();
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            NativeCrypto.SSL_CTX_free(sslCtxNativePointer);
        } finally {
            super.finalize();
        }
    }

    /**
     * Adds the given session to the cache.
     */
    final void cacheSession(SslSessionWrapper session) {
        byte[] id = session.getId();
        if (id == null || id.length == 0) {
            return;
        }

        // Let the subclass know.
        onBeforeAddSession(session);

        ByteArray key = new ByteArray(id);
        synchronized (sessions) {
            sessions.put(key, session);
        }
    }

    /**
     * Called for server sessions only. Retrieves the session by its ID. Overridden by
     * {@link ServerSessionContext} to
     */
    final SslSessionWrapper getSessionFromCache(byte[] sessionId) {
        if (sessionId == null) {
            return null;
        }

        // First, look in the in-memory cache.
        SslSessionWrapper session;
        synchronized (sessions) {
            session = sessions.get(new ByteArray(sessionId));
        }
        if (session != null && session.isValid()) {
            return session;
        }

        // Not found in-memory - look it up in the persistent cache.
        return getSessionFromPersistentCache(sessionId);
    }

    /**
     * Called when the given session is about to be added. Used by {@link ClientSessionContext} to
     * update its host-and-port based cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract void onBeforeAddSession(SslSessionWrapper session);

    /**
     * Called when a session is about to be removed. Used by {@link ClientSessionContext}
     * to update its host-and-port based cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract void onBeforeRemoveSession(SslSessionWrapper session);

    /**
     * Called for server sessions only. Retrieves the session by ID from the persistent cache.
     *
     * <p>Visible for extension only, not intended to be called directly.
     */
    abstract SslSessionWrapper getSessionFromPersistentCache(byte[] sessionId);

    /**
     * Makes sure cache size is < maximumSize.
     */
    private void trimToSize() {
        synchronized (sessions) {
            int size = sessions.size();
            if (size > maximumSize) {
                int removals = size - maximumSize;
                Iterator<SslSessionWrapper> i = sessions.values().iterator();
                while (removals-- > 0) {
                    SslSessionWrapper session = i.next();
                    onBeforeRemoveSession(session);
                    i.remove();
                }
            }
        }
    }
}
