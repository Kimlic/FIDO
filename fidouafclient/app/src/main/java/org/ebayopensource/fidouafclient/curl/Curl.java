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

package org.ebayopensource.fidouafclient.curl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.net.ssl.HostnameVerifier;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;

import android.os.AsyncTask;
import android.util.Log;

public class Curl {

  private static final String LOG_TAG = Curl.class.getSimpleName();

  private static String toStr(HttpResponse response) {
    try {
      InputStream in = response.getEntity().getContent();
      BufferedReader reader = new BufferedReader(new InputStreamReader(in));
      StringBuilder str = new StringBuilder();
      String line;

      while ((line = reader.readLine()) != null) {
        str.append(line).append("\n");
      }

      in.close();

      return str.toString();
    } catch (Exception ex) {
      return "Error";
    }
  }

  public static String getInSeparateThread(String url, String accountAddress) {
    GetAsyncTask async = new GetAsyncTask();
    async.execute(url, accountAddress);

    while (!async.isDone()) {
      try {
        Thread.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }

    return async.getResult();
  }

  public static String postInSeparateThread(String url, String header, String data) {
    PostAsyncTask async = new PostAsyncTask();
    async.execute(url, header, data);
    while (!async.isDone()) {
      try {
        Thread.sleep(1);
      } catch (InterruptedException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }
    return async.getResult();
  }

  public static String get(String url, String accountAddress) {
    String[] headers = {
        "Account-Address:" + accountAddress,
        "Content-Type:application/json",
        "Accept:application/vnd.mobile-api.v1+json"
    };

    return get(url, headers);
  }

  public static String get(String url, String[] headers) {
    try {
      Log.e(LOG_TAG, url);
      Log.e(LOG_TAG, headers.toString());

      HttpClient httpClient = getClient(url);
      HttpGet request = new HttpGet(url);

      try {
        if (headers != null) {
          for (String h : headers) {
            String[] split = h.split(":");
            request.addHeader(split[0], split[1]);
          }
        }

        HttpResponse response = httpClient.execute(request);
        return Curl.toStr(response);
      } catch (Exception ex) {
        ex.printStackTrace();

        return "{'error_code':'connect_fail','url':'" + url + "'}";
      }
    } catch (Exception e) {
      e.printStackTrace();

      return "{'error_code':'connect_fail','e':'" + e + "'}";
    }
  }

  public static String post(String url, String header, String data) {
    return post(url, header.split(" "), data);
  }

  public static String post(String url, String[] header, String data) {
    String ret = "";
    try {

      HttpClient httpClient = getClient(url);

      HttpPost request = new HttpPost(url);
      if (header != null) {
        for (String h : header) {
          String[] split = h.split(":");
          request.addHeader(split[0], split[1]);
        }
      }
      request.setEntity(new StringEntity(data));
      try {
        HttpResponse response = httpClient.execute(request);
        ret = Curl.toStr(response);
        Header[] headers = response.getAllHeaders();

      } catch (Exception ex) {
        ex.printStackTrace();
        ret = "{'error_code':'connect_fail','url':'" + url + "'}";
      }
    } catch (Exception e) {
      e.printStackTrace();
      ret = "{'error_code':'connect_fail','e':'" + e + "'}";
    }

    return ret;
  }

  private static HttpClient getClient(String url) {
    HttpClient httpClient = new DefaultHttpClient();
    if (url.toLowerCase().startsWith("https")) {
      httpClient = createHttpsClient();
    }
    return httpClient;
  }

  private static HttpClient createHttpsClient() {
    HostnameVerifier hostnameVerifier = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
    SchemeRegistry registry = new SchemeRegistry();
    SSLSocketFactory socketFactory = SSLSocketFactory.getSocketFactory();
    socketFactory
        .setHostnameVerifier((X509HostnameVerifier) hostnameVerifier);
    registry.register(new Scheme("https", socketFactory, 443));
    HttpClient client = new DefaultHttpClient();
    SingleClientConnManager mgr = new SingleClientConnManager(
        client.getParams(), registry);
    DefaultHttpClient httpClient = new DefaultHttpClient(mgr,
        client.getParams());
    return httpClient;
  }

}

class GetAsyncTask extends AsyncTask<String, Integer, String> {

  private String result = null;
  private boolean done = false;

  public boolean isDone() {
    return done;
  }

  public String getResult() {
    return result;
  }

  @Override
  protected String doInBackground(String... args) {
    result = Curl.get(args[0], args[1]);
    done = true;
    return result;
  }

  protected void onProgressUpdate(Integer... progress) {
  }

  protected void onPostExecute(String result) {
    this.result = result;
    done = true;
  }
}

class PostAsyncTask extends AsyncTask<String, Integer, String> {

  private String result = null;
  private boolean done = false;

  public boolean isDone() {
    return done;
  }

  public String getResult() {
    return result;
  }

  @Override
  protected String doInBackground(String... args) {
    result = Curl.post(args[0], args[1], args[2]);//(url, header, data)
    done = true;
    return result;
  }

  protected void onProgressUpdate(Integer... progress) {
  }

  @Override
  protected void onPostExecute(String result) {
    this.result = result;
    done = true;
  }
}
