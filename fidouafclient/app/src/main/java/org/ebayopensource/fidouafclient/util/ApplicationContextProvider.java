package org.ebayopensource.fidouafclient.util;

import android.app.Application;
import android.content.Context;

import java.security.Security;

public class ApplicationContextProvider extends Application {

  static {
    Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
  }
}
