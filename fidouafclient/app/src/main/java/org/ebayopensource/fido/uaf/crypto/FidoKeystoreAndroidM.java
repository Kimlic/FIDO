package org.ebayopensource.fido.uaf.crypto;

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

public class FidoKeystoreAndroidM extends FidoKeystore {

  // Constants

  private static final String TAG = FidoKeystoreAndroidM.class.getSimpleName();
  private static final int KEY_TIMEOUT_SECS = 60;

  // Variables

  private FingerprintManager mFingerprintManager;

  // Life

  FidoKeystoreAndroidM(FingerprintManager fingerprintManager) {
    mFingerprintManager = fingerprintManager;
  }

  @Override
  public KeyPair generateKeyPair(String username) {
    try {
      String keyId = getKeyId(username);
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
      KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN)
          .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
          .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
          .setUserAuthenticationRequired(true);

      if (!isFingerprintAuthAvailable())
        builder = builder.setUserAuthenticationValidityDurationSeconds(KEY_TIMEOUT_SECS);

      builder = builder.setAttestationChallenge(new byte[16]);
      builder = builder.setInvalidatedByBiometricEnrollment(false);

      keyPairGenerator.initialize(builder.build());

      return keyPairGenerator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public PublicKey getPublicKey(String accountAddress) {
    return getCertificate(accountAddress).getPublicKey();
  }

  @Override
  public X509Certificate getCertificate(String accountAddress) {
    try {
      String key = getKeyId(accountAddress);

      return (X509Certificate) getAndroidKeyStore().getCertificate(key);
    } catch (KeyStoreException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public FidoSigner getSigner(String username) {
    try {
      PrivateKey privateKey = (PrivateKey) getAndroidKeyStore().getKey(getKeyId(username), null);
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);

      return new FidoSignerAndroidM(signature);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  // Public

  public KeyPair getKeyPair(String username) {
    try {
      PublicKey pubKey = getPublicKey(username);
      PrivateKey privKey = (PrivateKey) getAndroidKeyStore().getKey(getKeyId(username), null);

      return new KeyPair(pubKey, privKey);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  // Private

  private boolean isFingerprintAuthAvailable() {
    return mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints();
  }

  private String getKeyId(String accountAddress) {
    return "com.kimlic.keystore.key_" + accountAddress;
  }

  private KeyStore getAndroidKeyStore() {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);

      return keyStore;
    } catch (GeneralSecurityException | IOException e) {
      throw new RuntimeException(e);
    }
  }
}
