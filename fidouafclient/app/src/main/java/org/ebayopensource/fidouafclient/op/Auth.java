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

package org.ebayopensource.fidouafclient.op;

import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.ebayopensource.fidouafclient.util.Endpoints;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.AuthenticatorSignAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fido.uaf.msg.asm.ASMRequest;
import org.ebayopensource.fido.uaf.msg.asm.Request;
import org.ebayopensource.fido.uaf.msg.asm.obj.AuthenticateIn;
import org.json.JSONObject;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;

import com.google.gson.Gson;

public class Auth {

  private Gson gson = new Gson();
  private SharedPreferences mPrefs;

  public Auth(Activity activity) {
    mPrefs = activity.getApplicationContext().getSharedPreferences("FIDO", 0);
  }

  public String getAsmRequestJson(int authenticatorIndex, String accountAddress) {
    return gson.toJson(getAsmRequest(authenticatorIndex, accountAddress));
  }

  public ASMRequest<AuthenticateIn> getAsmRequest(int authenticatorIndex, String accountAddress) {
    ASMRequest<AuthenticateIn> ret = new ASMRequest<AuthenticateIn>();
    ret.args = getAuthenticateIn(accountAddress);
    ret.asmVersion = new Version(1, 0);
    ret.authenticatorIndex = authenticatorIndex;
    ret.requestType = Request.Authenticate;
    return ret;
  }

  public String getUafMsgRequest(String facetId, Context context, boolean isTrx, String accountAddress) {
    String serverResponse = getAuthRequest(accountAddress);
    return OpUtils.getUafRequest(serverResponse, facetId, context, isTrx, accountAddress);
  }

  public String clientSendResponse(String uafMessage, String accountAddress) {
    return OpUtils.clientSendRegResponse(uafMessage, Endpoints.URL_AUTH_RESPONSE, accountAddress);
  }

  private String getAuthRequest(String accountAddress) {
    String url = Endpoints.URL_AUTH_REQUEST;
    return Curl.getInSeparateThread(url, accountAddress);
  }

  private AuthenticateIn getAuthenticateIn(String accountAddress) {
    AuthenticateIn ret = new AuthenticateIn();

    String url = Endpoints.URL_AUTH_REQUEST;
    String respFromServer = Curl.getInSeparateThread(url, accountAddress);
    AuthenticationRequest request = null;
    try {
      request = gson.fromJson(respFromServer, AuthenticationRequest[].class)[0];
      ret.appID = request.header.appID;
      ret.finalChallenge = getFinalChalenge(request);
      ret.keyIDs = new String[1];
      ret.keyIDs[0] = mPrefs.getString("keyID", "");
      freezeAuthResponse(request);
    } catch (Exception e) {

    }

    return ret;
  }

  private String getFinalChalenge(AuthenticationRequest request) {
    FinalChallengeParams fcParams = new FinalChallengeParams();
    fcParams.appID = request.header.appID;
    setSettings("appID", fcParams.appID);
    fcParams.facetID = getFacetId();
    fcParams.challenge = request.challenge;
    return Base64url.encodeToString(gson.toJson(
        fcParams).getBytes());
  }

  private String getFacetId() {
    return "";
  }

  public void freezeAuthResponse(AuthenticationRequest authRequest) {
    String json = gson.toJson(getAuthResponse(authRequest), AuthenticationResponse.class);
    setSettings("authResponse", json);
  }

  private AuthenticationResponse getAuthResponse(AuthenticationRequest authRequest) {
    AuthenticationResponse response = new AuthenticationResponse();

    response.header = new OperationHeader();
    response.header.serverData = authRequest.header.serverData;
    response.header.appID = authRequest.header.appID;
    response.header.op = authRequest.header.op;
    response.header.upv = authRequest.header.upv;
    response.fcParams = getFinalChalenge(authRequest);

    return response;
  }

  public String sendAuthResponse(String authOut) {
    String json = getAuthResponseForSending(authOut);
    String headerStr = "Content-Type:Application/json Accept:Application/json";
    String res = Curl.postInSeparateThread(Endpoints.URL_AUTH_RESPONSE, headerStr, json);
    return res;
  }

  private String getAuthResponseForSending(String authOut) {
    String ret = null;
    try {
      AuthenticationResponse authResponse = gson.fromJson(mPrefs.getString("authResponse", ""), AuthenticationResponse.class);
      JSONObject assertions = new JSONObject(authOut);
      authResponse.assertions = new AuthenticatorSignAssertion[1];
      authResponse.assertions[0] = new AuthenticatorSignAssertion();
      authResponse.assertions[0].assertionScheme = assertions.getJSONObject("responseData").getString("assertionScheme");
      authResponse.assertions[0].assertion = assertions.getJSONObject("responseData").getString("assertion");
      AuthenticationResponse[] forSending = new AuthenticationResponse[1];
      forSending[0] = authResponse;
      return gson.toJson(forSending, AuthenticationResponse[].class);
    } catch (Exception e) {
      e.printStackTrace();
    }

    return ret;
  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }
}
