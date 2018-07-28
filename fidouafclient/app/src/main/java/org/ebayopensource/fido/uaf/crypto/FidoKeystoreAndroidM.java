package org.ebayopensource.fido.uaf.crypto;

import android.app.Activity;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

public class FidoKeystoreAndroidM {

  // Constants

  private static final String LOG_TAG = FidoKeystoreAndroidM.class.getSimpleName();

  private static final int KEY_TIMEOUT_SECS = 60;
  private static final String KEYSTORE_NAME = "AndroidKeyStore";

  // Variables

  private FingerprintManager mFingerprintManager;

  // Public

  public static FidoKeystoreAndroidM createKeyStore(Activity activity) {
    FingerprintManager manager = activity.getSystemService(FingerprintManager.class);

    return new FidoKeystoreAndroidM(manager);
  }

  public KeyPair generateKeyPair(String accountAddress) {
    Log.e(LOG_TAG, "GENERATE: " + accountAddress);
    try {
      String keyId = getKeyId(accountAddress);
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_NAME);
      KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
          .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
          .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
          .setUserAuthenticationRequired(true);

      if (!isFingerprintAuthAvailable())
        builder = builder.setUserAuthenticationValidityDurationSeconds(KEY_TIMEOUT_SECS);

      builder = builder.setAttestationChallenge(new byte[16]);
      builder = builder.setInvalidatedByBiometricEnrollment(false);

      keyPairGenerator.initialize(builder.build());

      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      Log.d(LOG_TAG, "GEN KEYPAIR: " + keyPair);
      KeyStore keyStore = getAndroidKeyStore();
      X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyId);
      Log.d(LOG_TAG, "GEN CERT: " + cert);

      return keyPair;
    } catch (GeneralSecurityException e) {
      Log.e(LOG_TAG, "EXCEPTION: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  public FidoSigner getSigner(String accountAddress) {
    try {
      String keyId = getKeyId(accountAddress);
      PrivateKey privateKey = (PrivateKey) getAndroidKeyStore().getKey(keyId, null);
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);

      return new FidoSignerAndroidM(signature);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public KeyPair getKeyPair(String accountAddress) {
    try {
      PublicKey pubKey = getPublicKey(accountAddress);
      PrivateKey privKey = (PrivateKey) getAndroidKeyStore().getKey(getKeyId(accountAddress), null);

      return new KeyPair(pubKey, privKey);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  // Private

  private FidoKeystoreAndroidM(FingerprintManager fingerprintManager) {
    mFingerprintManager = fingerprintManager;
  }

  private PublicKey getPublicKey(String accountAddress) {
    return getCertificate(accountAddress).getPublicKey();
  }

  private X509Certificate getCertificate(String accountAddress) {
    try {
      Log.e(LOG_TAG, "AAAA: " + accountAddress);
      String key = getKeyId(accountAddress);
      Log.e(LOG_TAG, "BBBB: " + key);
      Log.e(LOG_TAG, "CCCC: " + getAndroidKeyStore().toString());
      Log.e(LOG_TAG, "DDDD: " + getAndroidKeyStore().getCertificate(key).toString());
      return (X509Certificate) getAndroidKeyStore().getCertificate(key);
    } catch (KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }

  private boolean isFingerprintAuthAvailable() {
    return mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints();
  }

  private String getKeyId(String accountAddress) {
    return "org.ebayopensource.fidouafclient.keystore.key_" + accountAddress;
  }

  private KeyStore getAndroidKeyStore() {
    try {
      KeyStore keyStore = KeyStore.getInstance(KEYSTORE_NAME);
      keyStore.load(null);

      return keyStore;
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }
}
