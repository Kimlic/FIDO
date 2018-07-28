package org.ebayopensource.fidouafclient;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Base64;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.ebayopensource.fidouafclient.util.Endpoints;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import static android.content.pm.PackageManager.GET_SIGNATURES;

public class UafService {

  public static String getFacetID(Context context) {
    try {
      context.getPackageManager();
      PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), GET_SIGNATURES);
      ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(info.signatures[0].toByteArray());
      Certificate certificate = CertificateFactory.getInstance("X509").generateCertificate(byteArrayInputStream);
      MessageDigest messageDigest = MessageDigest.getInstance("SHA1");

      return "android:apk-key-hash:" + Base64.encodeToString(messageDigest.digest(certificate.getEncoded()), 3);
    } catch (PackageManager.NameNotFoundException | CertificateException | NoSuchAlgorithmException e) {
      e.printStackTrace();

      return "";
    }
  }

  public static RegistrationRequest getRegistrationRequest(String accountAddress) {
    String regReq = Curl.getInSeparateThread(Endpoints.URL_REG_REQUEST, accountAddress);
    Gson gson = new Gson();

    return gson.fromJson(regReq, RegistrationRequest[].class)[0];
  }

  public static void deregRequest(Activity activity) {
    activity.startActivity(new Intent("info.gazers.log.FidoActivity"));
  }
}
