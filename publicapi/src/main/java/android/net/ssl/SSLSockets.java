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
}
