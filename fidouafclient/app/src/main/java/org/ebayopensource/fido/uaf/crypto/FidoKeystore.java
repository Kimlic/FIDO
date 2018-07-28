package org.ebayopensource.fido.uaf.crypto;

import android.app.Activity;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public abstract class FidoKeystore {

    public static FidoKeystore createKeyStore(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return new FidoKeystoreAndroidM(activity.getSystemService(FingerprintManager.class));
        }

        return new FidoKeyStoreBC(activity);
    }

    public abstract KeyPair generateKeyPair(String username);

    public abstract KeyPair getKeyPair(String username);

    public abstract PublicKey getPublicKey(String username);

    public abstract X509Certificate getCertificate(String username);

    public abstract FidoSigner getSigner(String username);
}
