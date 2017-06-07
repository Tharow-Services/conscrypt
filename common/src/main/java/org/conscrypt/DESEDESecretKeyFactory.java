package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation of {@link javax.crypto.SecretKeyFactory} for use with DESEDE keys.  This
 * class supports {@link SecretKeySpec} and {@link DESedeKeySpec} for key specs.
 *
 * @hide
 */
@Internal
public class DESEDESecretKeyFactory extends SecretKeyFactorySpi {
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Null KeySpec");
        }
        if (keySpec instanceof SecretKeySpec) {
            return (SecretKey) keySpec;
        } else if (keySpec instanceof DESedeKeySpec) {
            DESedeKeySpec desKeySpec = (DESedeKeySpec) keySpec;
            return new SecretKeySpec(desKeySpec.getKey(), "DESEDE");
        } else {
            throw new InvalidKeySpecException(
                    "Unsupported KeySpec class: " + keySpec.getClass().getName());
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey, Class<?> aClass)
            throws InvalidKeySpecException {
        if (secretKey == null) {
            throw new InvalidKeySpecException("Null SecretKey");
        }
        if (aClass == SecretKeySpec.class) {
            return (KeySpec) secretKey;
        } else if (aClass == DESedeKeySpec.class) {
            try {
                return new DESedeKeySpec(secretKey.getEncoded());
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            throw new InvalidKeySpecException("Unsupported KeySpec class: " + aClass.getName());
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey) throws InvalidKeyException {
        if (secretKey == null) {
            throw new InvalidKeyException("Null SecretKey");
        }
        return new SecretKeySpec(secretKey.getEncoded(), secretKey.getAlgorithm());
    }
}
