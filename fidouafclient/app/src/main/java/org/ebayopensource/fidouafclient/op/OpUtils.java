package org.ebayopensource.fidouafclient.op;


import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fido.uaf.msg.TrustedFacets;
import org.ebayopensource.fido.uaf.msg.TrustedFacetsList;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility Class for UaFRequest messages - Registration & Authentication
 */
public abstract class OpUtils {

  private static final String LOG_TAG = OpUtils.class.getSimpleName();

  /**
   * Process Request Message
   *
   * @param serverResponse Registration or Authentication request message
   * @param facetId        Application facet Id
   * @param context        Android Application Context
   * @param isTrx          always false for Registration messages. For Authentication it should be true only for transactions
   * @return uafProtocolMessage
   */

  private static JsonObject getServerResponseJson(String serverResponse) {
    return (JsonObject) new JsonParser().parse(serverResponse);
  }

  private static JsonArray getRequestJson(JsonObject json) {
    return json.getAsJsonObject("data").getAsJsonArray("request");
  }

  private static JsonObject getFirstRequestJson(JsonArray requestsJson) {
    return (JsonObject) requestsJson.get(0);
  }

  private static JsonObject getRequestHeader(JsonObject requestJson) {
    return requestJson.getAsJsonObject("header");
  }

  private static String getAppId(JsonObject headerJson) {
    return headerJson.getAsJsonPrimitive("appID").getAsString();
  }

  private static Version getVersion(JsonObject headerJson) {
    return (new Gson()).fromJson(headerJson.getAsJsonObject("upv").getAsString(), Version.class);
  }

  public static String getUafRequest(String serverResponse, String facetId, Context context, boolean isTrx, String accountAddress) {
    JsonObject serverResponseJson = getServerResponseJson(serverResponse);
    JsonArray requestArrayJson = getRequestJson(serverResponseJson);
    JsonObject requestJson = getFirstRequestJson(requestArrayJson);
    Log.e(LOG_TAG, "SERVER RESPONSE: \n" + requestJson.toString());
    JsonObject requestHeader = getRequestHeader(requestJson);

    String appID = getAppId(requestHeader);
//    Version version = getVersion(requestHeader);

    if (appID == null || appID.isEmpty()) {
      if (checkAppSignature(facetId, context)) {
        Log.e(LOG_TAG, "INVALID: appID not found");
//          requestHeader.addProperty("appID", facetId);
//          ((JsonObject) requestArray.get(0)).add("header", updatedJson);
      }
    } else {
      if (!facetId.equals(appID)) {
        Log.e(LOG_TAG, "INVALID: invalid facetID");
//          String trustedFacetsJson = getTrustedFacets(appID, accountAddress);
//          TrustedFacetsList trustedFacets = (new Gson()).fromJson(trustedFacetsJson, TrustedFacetsList.class);
//
//          if (trustedFacets.getTrustedFacets() == null) {
//            Log.e(LOG_TAG, "DDDD: " + requestArray.toString());
//            return getEmptyUafMsgRegRequest();
//          }
//
//          boolean facetFound = processTrustedFacetsList(trustedFacets, version, facetId);
//
//          if ((!facetFound) || (!checkAppSignature(facetId, context))) {
//            Log.e(LOG_TAG, "CCCC: " + requestArray.toString());
//
//            return getEmptyUafMsgRegRequest();
//          }
      } else if (!checkAppSignature(facetId, context))
        return getEmptyUafMsgRegRequest();
    }

    if (isTrx) {
      Log.e(LOG_TAG, "INVALID: invalid transaction");
//        JsonObject updateJson = (JsonObject) requestArray.get(0);
//        updateJson.add("transaction", getTransaction());
//        requestArray.set(0, updateJson);
    }

    JsonObject uafMsg = new JsonObject();
    uafMsg.add("uafProtocolMessage", requestArrayJson);

    return uafMsg.toString();
  }

  public static String getEmptyUafMsgRegRequest() {
    String msg = "{\"uafProtocolMessage\":";
    msg = msg + "\"\"";
    msg = msg + "}";
    return msg;
  }

  private static JsonArray getTransaction() {
    JsonArray ret = new JsonArray();
    JsonObject trx = new JsonObject();

    trx.addProperty("contentType", "text/plain");
    trx.addProperty("content", Base64url.encodeToString("Authentication".getBytes()));

    ret.add(trx);

    return ret;
  }

  /**
   * From among the objects in the trustedFacet array, select the one with the version matching
   * that of the protocol message version. The scheme of URLs in ids MUST identify either an
   * application identity (e.g. using the apk:, ios: or similar scheme) or an https: Web Origin [RFC6454].
   * Entries in ids using the https:// scheme MUST contain only scheme, host and port components,
   * with an optional trailing /. Any path, query string, username/password, or fragment information
   * MUST be discarded.
   *
   * @param trustedFacetsList
   * @param version
   * @param facetId
   * @return true if appID list contains facetId (current Android application's signature).
   */
  private static boolean processTrustedFacetsList(TrustedFacetsList trustedFacetsList, Version version, String facetId) {
    for (TrustedFacets trustedFacets : trustedFacetsList.getTrustedFacets()) {
      // select the one with the version matching that of the protocol message version
      if ((trustedFacets.getVersion().minor >= version.minor)
          && (trustedFacets.getVersion().major <= version.major)) {
        //The scheme of URLs in ids MUST identify either an application identity
        // (e.g. using the apk:, ios: or similar scheme) or an https: Web Origin [RFC6454].
        for (String id : trustedFacets.getIds()) {
          if (id.equals(facetId)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * A double check about app signature that was passed by MainActivity as facetID.
   *
   * @param facetId a string value composed by app hash. I.e. android:apk-key-hash:Lir5oIjf552K/XN4bTul0VS3GfM
   * @param context Application Context
   * @return true if the signature executed on runtime matches if signature sent by MainActivity
   */
  private static boolean checkAppSignature(String facetId, Context context) {
    try {
      PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
      for (Signature sign : packageInfo.signatures) {
        byte[] sB = sign.toByteArray();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
        messageDigest.update(sign.toByteArray());
        String currentSignature = Base64.encodeToString(messageDigest.digest(), Base64.DEFAULT);
        if (currentSignature.toLowerCase().contains(facetId.split(":")[2].toLowerCase())) {
          return true;
        }
      }
    } catch (PackageManager.NameNotFoundException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return false;
  }

  /**
   * Fetches the Trusted Facet List using the HTTP GET method. The location MUST be identified with
   * an HTTPS URL. A Trusted Facet List MAY contain an unlimited number of entries, but clients MAY
   * truncate or decline to process large responses.
   *
   * @param appID an identifier for a set of different Facets of a relying party's application.
   *              The AppID is a URL pointing to the TrustedFacets, i.e. list of FacetIDs related
   *              to this AppID.
   * @return Trusted Facets List
   */
  private static String getTrustedFacets(String appID, String accountAddress) {
    //TODO The caching related HTTP header fields in the HTTP response (e.g. “Expires”) SHOULD be respected when fetching a Trusted Facets List.
    return Curl.getInSeparateThread(appID, accountAddress);
  }

  public static String clientSendRegResponse(String uafMessage, String endpoint, String accountAddress) {
    try {
      String headers = "Account-Address:" + accountAddress + " Content-Type:application/json Accept:application/vnd.mobile-api.v1+json";
      JSONObject json = new JSONObject(uafMessage);
      String decoded = json.getString("uafProtocolMessage").replace("\\", "");

      return Curl.postInSeparateThread(endpoint, headers, decoded);
    } catch (JSONException e) {
      e.printStackTrace();

      return null;
    }
  }
}
