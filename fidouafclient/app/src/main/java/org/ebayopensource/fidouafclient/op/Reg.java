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
import org.ebayopensource.fido.uaf.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fido.uaf.msg.ChannelBinding;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.msg.asm.obj.RegisterIn;
import org.json.JSONArray;
import org.json.JSONObject;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


public class Reg {

  // Constants

  private static final String LOG_TAG = Reg.class.getSimpleName();

  // Variables

  private Gson gson = new GsonBuilder().disableHtmlEscaping().create();
  private SharedPreferences mPrefs;

  // Public

  public Reg(Activity activity) {
    mPrefs = activity.getApplicationContext().getSharedPreferences("FIDO", 0);
  }

  public String getUafMsgRegRequest(String accountAddress, String facetId, Context context) {
    Log.e(LOG_TAG, "GET UAF MSG REG REQUEST");

    String serverResponse = getRegRequest(accountAddress);
    Log.e(LOG_TAG, "serverResponse: " + serverResponse);

    return OpUtils.getUafRequest(serverResponse, facetId, context, false, accountAddress);
  }

//  public RegisterIn getRegIn(String username) {
//    RegisterIn ret = new RegisterIn();
//    String url = Endpoints.URL_REG_REQUEST;
//    String regRespFromServer = Curl.getInSeparateThread(url);
//    RegistrationRequest regRequest = null;
//    try {
//      regRequest = gson.fromJson(regRespFromServer, RegistrationRequest[].class)[0];
//      ret.appID = regRequest.header.appID;
//      ret.attestationType = 15879;
//      ret.finalChallenge = getFinalChalenge(regRequest);
//      ret.username = username;
//      freezeRegResponse(regRequest);
//    } catch (Exception ignored) {
//
//    }
//
//    return ret;
//  }

  public String clientSendRegResponse(String uafMessage, String accountAddress) {
    String serverResponse = OpUtils.clientSendRegResponse(uafMessage, Endpoints.URL_REG_RESPONSE, accountAddress);
    Log.e(LOG_TAG, "REG RESPONSE:\n" + serverResponse);
    saveAAIDandKeyID(serverResponse);

    return serverResponse;
  }

  public String sendRegResponse(String regOut) {
    StringBuilder res = new StringBuilder();
    res.append("{regOut}").append(regOut);
    String json = getRegResponseForSending(regOut);
    res.append("{regResponse}").append(json);
    String headerStr = "Content-Type:Application/json Accept:Application/json";
    res.append("{ServerResponse}");
    String serverResponse = Curl.postInSeparateThread(Endpoints.URL_REG_RESPONSE, headerStr, json);
    res.append(serverResponse);
    saveAAIDandKeyID(serverResponse);
    return res.toString();
  }

  private String getRegRequest(String accountAddress) {
    String url = Endpoints.URL_REG_REQUEST;

    return Curl.getInSeparateThread(url, accountAddress);
  }

  private static JsonObject getServerResponseJson(String serverResponse) {
    return (JsonObject) new JsonParser().parse(serverResponse);
  }

  private static JsonArray getResponseJson(JsonObject json) {
    return json.getAsJsonObject("data").getAsJsonArray("response");
  }

  private static JsonObject getFirstRequestJson(JsonArray requestsJson) {
    return (JsonObject) requestsJson.get(0);
  }

  private static JsonObject getAuthenticatorJson(JsonObject requestJson) {
    return requestJson.getAsJsonObject("authenticator");
  }

  private void saveAAIDandKeyID(String res) {
    try {
      JsonObject responseObject = getServerResponseJson(res);
      JsonArray responsesJson = getResponseJson(responseObject);
      JsonObject responseJson = getFirstRequestJson(responsesJson);
      JsonObject authenticatorJson = getAuthenticatorJson(responseJson);
      String aaid = authenticatorJson.get("AAID").getAsString();
      String keyId = authenticatorJson.get("KeyID").getAsString();
      Log.e(LOG_TAG, "AAID: " + aaid + ",   KEYID: " + keyId);
      setSettings("AAID", aaid);
      setSettings("keyID", keyId);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private String getRegResponseForSending(String regOut) {
    try {
      RegistrationResponse regResponse = gson.fromJson(mPrefs.getString("regResponse", ""), RegistrationResponse.class);
      JSONObject assertions = new JSONObject(regOut);
      regResponse.assertions = new AuthenticatorRegistrationAssertion[1];
      regResponse.assertions[0] = new AuthenticatorRegistrationAssertion();
      regResponse.assertions[0].assertionScheme = assertions.getJSONObject("responseData").getString("assertionScheme");
      regResponse.assertions[0].assertion = assertions.getJSONObject("responseData").getString("assertion");
      RegistrationResponse[] forSending = new RegistrationResponse[1];
      forSending[0] = regResponse;

      return gson.toJson(forSending, RegistrationResponse[].class);
    } catch (Exception e) {
      e.printStackTrace();

      return null;
    }
  }

  private String getFinalChalenge(RegistrationRequest regRequest) {
    FinalChallengeParams fcParams = new FinalChallengeParams();
    fcParams.appID = regRequest.header.appID;
    setSettings("appID", fcParams.appID);
    fcParams.facetID = getFacetId();
    fcParams.challenge = regRequest.challenge;
    fcParams.channelBinding = new ChannelBinding();
    fcParams.channelBinding.cid_pubkey = "";
    fcParams.channelBinding.serverEndPoint = "";
    fcParams.channelBinding.tlsServerCertificate = "";
    fcParams.channelBinding.tlsUnique = "";

    return Base64url.encodeToString(gson.toJson(fcParams).getBytes());
  }

  private String getFacetId() {
    return "";
  }

  private void freezeRegResponse(RegistrationRequest regRequest) {
    String json = gson.toJson(getRegResponse(regRequest), RegistrationResponse.class);
    setSettings("regResponse", json);
  }

  private RegistrationResponse getRegResponse(RegistrationRequest regRequest) {
    RegistrationResponse response = new RegistrationResponse();

    response.header = new OperationHeader();
    response.header.serverData = regRequest.header.serverData;
    response.header.appID = regRequest.header.appID;
    response.header.op = regRequest.header.op;
    response.header.upv = regRequest.header.upv;
    response.fcParams = getFinalChalenge(regRequest);

    return response;
  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }
}
