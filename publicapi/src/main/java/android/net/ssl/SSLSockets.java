package android.net.ssl;

import com.android.org.conscrypt.Conscrypt;

import javax.net.ssl.SSLSocket;

/**
 * Static utility methods for accessing additional functionality of supported instances of
 * {@link SSLSocket}.  Sockets from the platform TLS provider will be compatible with all
 * methods in this class.
 */
public class SSLSockets {
    private SSLSockets() {}

    /**
     * Returns whether the given socket can be used with the methods in this class.  In general,
     * only sockets from the platform TLS provider are supported.
     */
    public static boolean isSupportedSocket(SSLSocket socket) {
        return Conscrypt.isConscrypt(socket);
    }

    private static void checkSupported(SSLSocket s) {
        if (!isSupportedSocket(s)) {
            throw new IllegalArgumentException("Socket is not a supported socket.");
        }
    }

    /**
     * Enables or disables the use of session tickets.
     *
     * <p>This function must be called before the handshake is started.
     *
     * @param socket the socket
     * @param useSessionTickets whether to enable or disable the use of session tickets
     * @throws IllegalArgumentException if the given socket is not a platform socket
     */
    public static void setUseSessionTickets(SSLSocket socket, boolean useSessionTickets) {
        checkSupported(socket);
        Conscrypt.setUseSessionTickets(socket, useSessionTickets);
    }

    /**
     * Sets the application-layer protocols (ALPN) in prioritization order.  By default, ALPN is
     * disabled.
     *
     * <p>This function must be called before the handshake is started.
     *
     * @param socket the socket
     * @param protocols the protocols in descending order of preference.  If empty, ALPN will be
     * disabled.  This array will be copied.
     * @throws IllegalArgumentException - if protocols is null, if any element is null or
     * an empty string, or if the given socket is not a platform socket
     */
    public static void setApplicationProtocols(SSLSocket socket, String[] protocols) {
        checkSupported(socket);
        Conscrypt.setApplicationProtocols(socket, protocols);
    }

    /**
     * Gets the application-layer protocols (ALPN) in prioritization order.
     *
     * @param socket the socket
     * @return the protocols in descending order of preference, or an empty array if protocol
     * indications are not being used. Always returns a new array.
     * @throws IllegalArgumentException if the given socket is not a platform socket
     */
    public static String[] getApplicationProtocols(SSLSocket socket) {
        checkSupported(socket);
        return Conscrypt.getApplicationProtocols(socket);
    }

    /**
     * Returns the ALPN protocol agreed upon by the client and the server.
     *
     * @param socket the socket
     * @return the selected protocol or {@code null} if no protocol was agreed upon or the
     * handshake has not yet completed
     * @throws IllegalArgumentException if the given socket is not a platform socket
     */
    public static String getApplicationProtocol(SSLSocket socket) {
        checkSupported(socket);
        return Conscrypt.getApplicationProtocol(socket);
    }
}
