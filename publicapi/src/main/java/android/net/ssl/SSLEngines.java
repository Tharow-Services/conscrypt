package android.net.ssl;

import com.android.org.conscrypt.Conscrypt;

import javax.net.ssl.SSLEngine;

/**
 * Static utility methods for accessing additional functionality of supported instances of
 * {@link SSLEngine}.  Engines from the platform TLS provider will be compatible with all
 * methods in this class.
 */
public class SSLEngines {
    private SSLEngines() {}

    /**
     * Returns whether the given engine can be used with the methods in this class.  In general,
     * only engines from the platform TLS provider are supported.
     */
    public static boolean isSupportedEngine(SSLEngine engine) {
        return Conscrypt.isConscrypt(engine);
    }

    private static void checkSupported(SSLEngine e) {
        if (!isSupportedEngine(e)) {
            throw new IllegalArgumentException("Engine is not a supported engine.");
        }
    }

    /**
     * Enables or disables the use of session tickets.
     *
     * <p>This function must be called before the handshake is started.
     *
     * @param engine the engine
     * @param useSessionTickets whether to enable or disable the use of session tickets
     * @throws IllegalArgumentException if the given engine is not a platform engine
     */
    public static void setUseSessionTickets(SSLEngine engine, boolean useSessionTickets) {
        checkSupported(engine);
        Conscrypt.setUseSessionTickets(engine, useSessionTickets);
    }

    /**
     * Sets the application-layer protocols (ALPN) in prioritization order.  By default, ALPN is
     * disabled.
     *
     * <p>This function must be called before the handshake is started.
     *
     * @param engine the engine
     * @param protocols the protocols in descending order of preference.  If empty, ALPN will be
     * disabled.  This array will be copied.
     * @throws IllegalArgumentException - if protocols is null, if any element is null or
     * an empty string, or if the given engine is not a platform engine
     */
    public static void setApplicationProtocols(SSLEngine engine, String[] protocols) {
        checkSupported(engine);
        Conscrypt.setApplicationProtocols(engine, protocols);
    }

    /**
     * Gets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param engine the engine
     * @return the protocols in descending order of preference, or an empty array if protocol
     * indications are not being used. Always returns a new array.
     * @throws IllegalArgumentException if the given engine is not a platform engine
     */
    public static String[] getApplicationProtocols(SSLEngine engine) {
        checkSupported(engine);
        return Conscrypt.getApplicationProtocols(engine);
    }

    /**
     * Returns the ALPN protocol agreed upon by the client and the server.
     *
     * @param engine the engine
     * @return the selected protocol or {@code null} if no protocol was agreed upon or the
     * handshake has not yet completed
     * @throws IllegalArgumentException if the given engine is not a platform engine
     */
    public static String getApplicationProtocol(SSLEngine engine) {
        checkSupported(engine);
        return Conscrypt.getApplicationProtocol(engine);
    }
}
