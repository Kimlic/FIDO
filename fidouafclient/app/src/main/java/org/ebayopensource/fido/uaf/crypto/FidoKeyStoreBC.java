package org.ebayopensource.fido.uaf.crypto;

import android.app.Activity;
import android.content.SharedPreferences;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

public class FidoKeyStoreBC extends FidoKeystore {

  private SharedPreferences mPrefs;

  FidoKeyStoreBC(Activity activity) {
    mPrefs = activity.getApplicationContext().getSharedPreferences("FIDO", 0);
  }

  @Override
  public KeyPair generateKeyPair(String username) {
    try {
      ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");
      g.initialize(ecGenSpec, new SecureRandom());
      KeyPair keyPair = g.generateKeyPair();

      setSettings("pub", Base64url.encodeToString(keyPair.getPublic().getEncoded()));
      setSettings("priv", Base64url.encodeToString(keyPair.getPrivate().getEncoded()));

      return keyPair;
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public KeyPair getKeyPair(String username) {
    try {
      String prefPriv = mPrefs.getString("priv", "");
      PublicKey pubKey = getPublicKey(username);
      PrivateKey privKey = KeyCodec.getPrivKey(Base64url.decode(prefPriv));

      return new KeyPair(pubKey, privKey);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public PublicKey getPublicKey(String username) {
    try {
      String prefPub = mPrefs.getString("pub", "");

      return KeyCodec.getPubKey(Base64url.decode(prefPub));
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public X509Certificate getCertificate(String username) {
    // XXX -- not implemented as no cert
    return null;
  }

  @Override
  public FidoSigner getSigner(String username) {
    // XXX doesn't use username ATM
    return new FidoSignerBC();
  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }
}
