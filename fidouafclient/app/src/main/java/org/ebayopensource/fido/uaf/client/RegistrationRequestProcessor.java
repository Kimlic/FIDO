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

package org.ebayopensource.fido.uaf.client;

import android.app.Activity;
import android.content.SharedPreferences;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fido.uaf.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;

import java.security.KeyPair;


public class RegistrationRequestProcessor {

  private SharedPreferences mPrefs;
  private Activity mActivity;

  public RegistrationRequestProcessor(Activity activity) {
    mActivity = activity;
    mPrefs = activity.getApplicationContext().getSharedPreferences("FIDO", 0);
  }

  public RegistrationResponse processRequest(RegistrationRequest regRequest, KeyPair keyPair) {
    RegistrationResponse response = new RegistrationResponse();
    RegAssertionBuilder builder = new RegAssertionBuilder(keyPair, mActivity);
    Gson gson = new Gson();


    setAppId(regRequest, response);
    response.header = new OperationHeader();
    response.header.serverData = regRequest.header.serverData;
    response.header.appID = regRequest.header.appID;
    response.header.op = regRequest.header.op;
    response.header.upv = regRequest.header.upv;

    FinalChallengeParams fcParams = new FinalChallengeParams();
    fcParams.appID = regRequest.header.appID;
    setSettings("appID", fcParams.appID);
    fcParams.facetID = getFacetId();
    fcParams.challenge = regRequest.challenge;
    response.fcParams = Base64url.encodeToString(gson.toJson(
        fcParams).getBytes());
    setAssertions(response, builder);
    return response;
  }

  private String getFacetId() {
    return "";
  }

  private void setAssertions(RegistrationResponse response, RegAssertionBuilder builder) {
    response.assertions = new AuthenticatorRegistrationAssertion[1];
    try {
      response.assertions[0] = new AuthenticatorRegistrationAssertion();
      response.assertions[0].assertion = builder.getAssertions(response);
      response.assertions[0].assertionScheme = "UAFV1TLV";
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }

  private void setAppId(RegistrationRequest regRequest,
                        RegistrationResponse response) {
    // TODO Auto-generated method stub

  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }

}
