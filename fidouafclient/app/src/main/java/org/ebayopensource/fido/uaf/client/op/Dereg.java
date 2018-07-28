/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fido.uaf.client.op;

import android.app.Activity;
import android.content.SharedPreferences;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.RegAssertionBuilder;
import org.ebayopensource.fido.uaf.msg.DeregisterAuthenticator;
import org.ebayopensource.fido.uaf.msg.DeregistrationRequest;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Version;

import java.util.logging.Logger;

public class Dereg {

  private Logger logger = Logger.getLogger(this.getClass().getName());
  private Gson gson = new Gson();
  private SharedPreferences mPrefs;

  public Dereg(Activity activity) {
    mPrefs = activity.getApplicationContext().getSharedPreferences("FIDO", 0);
  }

  public String dereg(String uafMsg) {
    try {
      DeregistrationRequest reg = new DeregistrationRequest();
      reg.header = new OperationHeader();
      reg.header.upv = new Version(1, 0);
      reg.header.op = Operation.Dereg;
      reg.header.appID = mPrefs.getString("appID", "");
      reg.authenticators = new DeregisterAuthenticator[1];
      DeregisterAuthenticator deregAuth = new DeregisterAuthenticator();
      deregAuth.aaid = RegAssertionBuilder.AAID;
      String tmp = mPrefs.getString("keyId", "");
      byte[] bytes = tmp.getBytes();
      deregAuth.keyID = tmp;
//				Base64.encodeToString(bytes, Base64.NO_WRAP);
      reg.authenticators[0] = deregAuth;

      logger.info("  [UAF][2]Dereg - Reg Response Formed  ");
      setSettings("pub", "");
      setSettings("priv", "");
      setSettings("username", "");
      setSettings("keyId", "");

      return gson.toJson(reg);
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return "";
  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }
}
