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

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.RegistrationRequestProcessor;
import org.ebayopensource.fido.uaf.crypto.FidoKeystoreAndroidM;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;

import java.security.KeyPair;

public class Reg {

  // Public

  public static String register(String uafMsg, String accountAddress, FidoKeystoreAndroidM fidoKeystore, Activity activity) {
    RegistrationResponse[] ret = new RegistrationResponse[1];
    ret[0] = regResponse(uafMsg, accountAddress, fidoKeystore, activity);

    return getUafProtocolMsg(new Gson().toJson(ret));
  }

  // Private

  private static RegistrationResponse regResponse(String uafMsg, String accountAddress, FidoKeystoreAndroidM fidoKeystore, Activity activity) {
    KeyPair keyPair = fidoKeystore.generateKeyPair(accountAddress);
    RegistrationRequestProcessor p = new RegistrationRequestProcessor(activity);

    return p.processRequest(getRegistrationRequest(uafMsg), keyPair);
  }

  private static RegistrationRequest getRegistrationRequest(String uafMsg) {
    return new Gson().fromJson(uafMsg, RegistrationRequest[].class)[0];
  }

  private static String getUafProtocolMsg(String uafMsg) {
    return String.format("{\"uafProtocolMessage\":\"%s\"}", uafMsg.replace("\"", "\\\""));
  }
}
