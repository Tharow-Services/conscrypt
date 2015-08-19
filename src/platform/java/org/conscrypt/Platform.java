/*
 * Copyright 2013 The Android Open Source Project
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

import static android.system.OsConstants.SOL_SOCKET;
import static android.system.OsConstants.SO_SNDTIMEO;

import org.apache.harmony.security.utils.AlgNameMapper;
import org.apache.harmony.security.utils.AlgNameMapperSource;
import org.conscrypt.GCMParameters;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructTimeval;
import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.List;
import java.util.Collections;
import java.util.Arrays;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

class Platform {
    private static class NoPreloadHolder {
        public static final Platform MAPPER = new Platform();
    }

    /**
     * Runs all the setup for the platform that only needs to run once.
     */
    public static void setup() {
        NoPreloadHolder.MAPPER.ping();
    }

    /**
     * Just a placeholder to make sure the class is initialized.
     */
    private void ping() {
    }

    private Platform() {
        AlgNameMapper.setSource(new OpenSSLMapper());
    }

    private static class OpenSSLMapper implements AlgNameMapperSource {
        @Override
        public String mapNameToOid(String algName) {
            return NativeCrypto.OBJ_txt2nid_oid(algName);
        }

        @Override
        public String mapOidToName(String oid) {
            return NativeCrypto.OBJ_txt2nid_longName(oid);
        }
    }

    public static FileDescriptor getFileDescriptor(Socket s) {
        return s.getFileDescriptor$();
    }

    public static FileDescriptor getFileDescriptorFromSSLSocket(OpenSSLSocketImpl openSSLSocketImpl) {
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(openSSLSocketImpl);
            Field f_fd = SocketImpl.class.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    public static String getCurveName(ECParameterSpec spec) {
        return spec.getCurveName();
    }

    public static void setCurveName(ECParameterSpec spec, String curveName) {
        spec.setCurveName(curveName);
    }

    public static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        StructTimeval tv = StructTimeval.fromMillis(timeoutMillis);
        try {
            Os.setsockoptTimeval(s.getFileDescriptor$(), SOL_SOCKET, SO_SNDTIMEO, tv);
        } catch (ErrnoException errnoException) {
            throw errnoException.rethrowAsSocketException();
        }
    }

    public static void checkServerTrusted(X509TrustManager x509tm, X509Certificate[] chain,
            String authType, String host) throws CertificateException {
        if (x509tm instanceof TrustManagerImpl) {
            TrustManagerImpl tm = (TrustManagerImpl) x509tm;
            tm.checkServerTrusted(chain, authType, host);
        } else {
            x509tm.checkServerTrusted(chain, authType);
        }
    }

    /**
     * Wraps an old AndroidOpenSSL key instance. This is not needed on platform
     * builds since we didn't backport, so return null.
     */
    public static OpenSSLKey wrapRsaKey(PrivateKey key) {
        return null;
    }

    /**
     * Logs to the system EventLog system.
     */
    public static void logEvent(String message) {
        try {
            Class processClass = Class.forName("android.os.Process");
            Object processInstance = processClass.newInstance();
            Method myUidMethod = processClass.getMethod("myUid", (Class[]) null);
            int uid = (Integer) myUidMethod.invoke(processInstance);

            Class eventLogClass = Class.forName("android.util.EventLog");
            Object eventLogInstance = eventLogClass.newInstance();
            Method writeEventMethod = eventLogClass.getMethod("writeEvent",
                    new Class[] { Integer.TYPE, Object[].class });
            writeEventMethod.invoke(eventLogInstance, 0x534e4554 /* SNET */,
                    new Object[] { "conscrypt", uid, message });
        } catch (Exception e) {
            // Do not log and fail silently
        }
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    public static boolean isLiteralIpAddress(String hostname) {
        return InetAddress.isNumeric(hostname);
    }

    /**
     * Wrap the SocketFactory with the platform wrapper if needed for compatability.
     * For the platform-bundled library we never need to wrap.
     */
    public static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        return factory;
    }

    /**
     * Convert from platform's GCMParameterSpec to our internal version.
     */
    public static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        if (params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParams = (GCMParameterSpec) params;
            return new GCMParameters(gcmParams.getTLen(), gcmParams.getIV());
        }
        return null;
    }

    /**
     * Creates a platform version of {@code GCMParameterSpec}.
     */
    public static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        return new GCMParameterSpec(tagLenInBits, iv);
    }
    /**
     * Check if SCT verification is enforced for a given hostname.
     *
     * SCT Verification is enabled using {@code Security} properties.
     * The "conscrypt.ct.enable" property must be true, as well as a per domain property.
     * The reverse notation of the domain name, prefixed with "conscrypt.ct.enforce."
     * is used as the property name.
     * Basic globbing is also supported.
     *
     * For example, for the domain foo.bar.com, the following properties will be
     * looked up, in order of precedence.
     * - conscrypt.ct.enforce.com.bar.foo
     * - conscrypt.ct.enforce.com.bar.*
     * - conscrypt.ct.enforce.com.*
     * - conscrypt.ct.enforce.*
     */
    public static boolean isCTVerificationEnabled(String hostname) {
        Boolean property = getBooleanSecurityProperty("conscrypt.ct.enable");
        if (property == null || property == Boolean.FALSE) {
            return false;
        }

        List<String> parts = Arrays.asList(hostname.split("\\."));
        Collections.reverse(parts);

        boolean enable = false;

        String propertyName = "conscrypt.ct.enforce";
        for (String part: parts) {
            property = getBooleanSecurityProperty(propertyName + ".*");
            if (property != null) {
                enable = property;
            }

            propertyName = propertyName + "." + part;
        }

        property = getBooleanSecurityProperty(propertyName);
        if (property != null) {
            enable = property;
        }

        return enable;
    }

    private static Boolean getBooleanSecurityProperty(String name) {
        String property = Security.getProperty(name);
        if (property == null) {
            return null;
        }
        property = property.toLowerCase();

        switch (property) {
            case "true":
            case "yes":
            case "on":
            case "1":
                return Boolean.TRUE;
            case "false":
            case "no":
            case "off":
            case "0":
                return Boolean.FALSE;
            default:
                return null;
        }
    }
}
