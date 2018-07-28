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

package org.ebayopensource.fidouafclient;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.ebayopensource.fido.uaf.msg.client.UAFIntentType;
import org.ebayopensource.fidouafclient.op.Auth;
import org.ebayopensource.fidouafclient.op.Dereg;
import org.ebayopensource.fidouafclient.op.OpUtils;
import org.ebayopensource.fidouafclient.op.Reg;
import org.ebayopensource.fidouafclient.util.ApplicationContextProvider;

import java.util.Objects;

public class MainActivity extends Activity {

  // Constants

  private static final String LOG_TAG = MainActivity.class.getSimpleName();

  private static final int REG_RESULT = 3;
  private static final int DEREG_RESULT = 4;
  private static final int AUTH_RESULT = 5;

  private static final String ACCOUNT_ADDRESS = "0xdfbc3489041d9c3c728b4179c3c358c143c7e98e";

  // Variables

  private TextView mMsgTextView;
  private TextView mTitleTextView;
  private TextView mFacetTextView;
  private EditText mEditTextName;

  private Reg mReg;
  private Dereg mDereg;
  private Auth mAuth;
  private SharedPreferences mPrefs;

  // Life

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    mPrefs = getApplicationContext().getSharedPreferences("FIDO", 0);
    mReg = new Reg(this);
    mDereg = new Dereg(this);
    mAuth = new Auth(this);

    boolean isNotRegistered = mPrefs.getString("keyID", "").equals("");
    setContentView(isNotRegistered ? R.layout.activity_main : R.layout.activity_registered);

    findFields();
    assignUserAddress();
    assignFacetId();
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    getMenuInflater().inflate(R.menu.main, menu);

    return true;
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    int id = item.getItemId();

    if (id == R.id.action_discover)
      info(this.getWindow().getCurrentFocus());

    return super.onOptionsItemSelected(item);
  }

  @SuppressLint("SetTextI18n")
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (resultCode == RESULT_CANCELED) {
      showToast(data.getExtras().getString("message"));

      return;
    }

    if (resultCode != RESULT_OK) {
      showToast("Wrong result");

      return;
    }

    StringBuilder extras = composeExtras(data, resultCode);
    mTitleTextView.setText("extras=" + extras.toString());

    switch (requestCode) {
      case 1: optionOne(data); return;
      case 2: optionTwo(data); return;
      case REG_RESULT: userReged(data, extras); return;
      case DEREG_RESULT: userDereged(data, extras); return;
      case AUTH_RESULT: userAuthed(data);
    }
  }

  private void optionOne(Intent data) {
//    Log.e(LOG_TAG, "OPTION 1");
//    String asmResponse = data.getStringExtra("message");
//    String discoveryData = data.getStringExtra("discoveryData");
//    mMsgTextView.setText(String.format("{message}%s{discoveryData}%s", asmResponse, discoveryData));
  }

  private void optionTwo(Intent data) {
//    Log.e(LOG_TAG, "OPTION 2");
//    String asmResponse = data.getStringExtra("message");
//    mMsgTextView.setText(asmResponse);
//    mDereg.recordKeyId(asmResponse);
  }

  private void userReged(Intent data, StringBuilder extras) {
//    Log.e(LOG_TAG, "OPTION 3");
//    try {
//      String uafMessage = data.getStringExtra("message");
//      mMsgTextView.setText(uafMessage);
//
//      String res = mReg.clientSendRegResponse(uafMessage);
//      setContentView(R.layout.activity_registered);
//
//      findFields();
//
//      mTitleTextView.setText(String.format("extras=%s", extras.toString()));
//      mMsgTextView.setText(res);
//      mEditTextName.setText(ACCOUNT_ADDRESS);
//    } catch (Exception e) {
//      mMsgTextView.setText(String.format("Registration operation failed.\n%s", e));
//    }
  }

  private void userAuthed(Intent data) {
//    Log.e(LOG_TAG, "OPTION 5");
//    String uafMessage = data.getStringExtra("message");
//
//    if (uafMessage == null)
//      return;
//
//    mMsgTextView.setText(uafMessage);
//
//    String res = mAuth.clientSendResponse(uafMessage);
//    mMsgTextView.setText(res);
  }

  private void userDereged(Intent data, StringBuilder extras) {
//    Log.e(LOG_TAG, "OPTION 4");
//    Preferences.setSettingsParam("keyID", "");
//    mPrefs.
//
//    setContentView(R.layout.activity_main);
//
//    findFields();
//
//    mTitleTextView.setText(String.format("extras=%s", extras.toString()));
//    String message = data.getStringExtra("message");
//
//    if (message != null) {
//      String out = "Dereg done. Client msg=" + message;
//      out = out + ". Sent=" + mDereg.clientSendDeregResponse(message);
//      mMsgTextView.setText(out);
//    } else {
//      String deregMsg = Preferences.getSettingsParam("deregMsg");
//      String out = "Dereg done. Client msg was empty. Dereg msg = " + deregMsg;
//      out = out + ". Response=" + mDereg.post(deregMsg);
//      mMsgTextView.setText(out);
//    }
  }

  // Actions

  public void assignUserAddress() {
    mEditTextName.setText(ACCOUNT_ADDRESS);
  }

  public void assignFacetId() {
    String facetId = UafService.getFacetID(this);
    mFacetTextView.setText(facetId);
  }

  @SuppressLint("SetTextI18n")
  public void info(View view) {
//    Log.e(LOG_TAG, "INFO ACTION");
//
//    mTitleTextView.setText("Discovery info");
//
//    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
//    i.addCategory("android.intent.category.DEFAULT");
//    i.setType("application/fido.uaf_client+json");
//
//    Bundle data = new Bundle();
//    data.putString("message", OpUtils.getEmptyUafMsgRegRequest());
//    data.putString("UAFIntentType", UAFIntentType.DISCOVER.name());
//    i.putExtras(data);
//    startActivityForResult(i, 1);
  }

  // Private

  @SuppressLint("SetTextI18n")
  public void regRequestAction(View view) {
    Log.e(LOG_TAG, "REG REQUEST ACTION");

    String facetId = UafService.getFacetID(this);
    Log.e(LOG_TAG, "facetId: " + facetId);

    String regRequest = mReg.getUafMsgRegRequest(ACCOUNT_ADDRESS, facetId, this);
    Log.e(LOG_TAG, "message, channelBindings: " + regRequest);

    String intentType = UAFIntentType.UAF_OPERATION.name();
    Log.e(LOG_TAG, "UAFIntentType: " + intentType);

    Bundle data = new Bundle();
    data.putString("message", regRequest);
    data.putString("UAFIntentType", intentType);
    data.putString("channelBindings", regRequest);

    Intent intent = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
    intent.addCategory("android.intent.category.DEFAULT");
    intent.setType("application/fido.uaf_client+json");
    intent.putExtras(data);
    startActivityForResult(intent, REG_RESULT);
  }

  @SuppressLint("SetTextI18n")
  public void dereg(View view) {
//    Log.e(LOG_TAG, "DEREG");
//
//    mTitleTextView.setText("Deregistration operation executed");
//
//    String uafMessage = mDereg.getUafMsgRequest();
//    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
//    i.addCategory("android.intent.category.DEFAULT");
//    i.setType("application/fido.uaf_client+json");
//
//    Bundle data = new Bundle();
//    data.putString("message", uafMessage);
//    data.putString("UAFIntentType", "UAF_OPERATION");
//    data.putString("channelBindings", uafMessage);
//    i.putExtras(data);
//    startActivityForResult(i, DEREG_RESULT);
  }

  @SuppressLint("SetTextI18n")
  public void authRequest(View view) {
//    Log.e(LOG_TAG, "AUTH REQUEST");
//
//    mTitleTextView.setText("Authentication operation executed");
//
//    String authRequest = mAuth.getUafMsgRequest(UafService.getFacetID(this), this, false);
//    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
//    i.addCategory("android.intent.category.DEFAULT");
//    i.setType("application/fido.uaf_client+json");
//    Bundle data = new Bundle();
//    data.putString("message", authRequest);
//    data.putString("UAFIntentType", "UAF_OPERATION");
//    data.putString("channelBindings", authRequest);
//    i.putExtras(data);
//    startActivityForResult(i, AUTH_RESULT);
  }

  @SuppressLint("SetTextI18n")
  public void trxRequest(View view) {
//    Log.e(LOG_TAG, "TRX REQUEST");
//
//    mTitleTextView.setText("Authentication operation executed");
//
//    String authRequest = mAuth.getUafMsgRequest(UafService.getFacetID(this), this, true);
//
//    Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
//    i.addCategory("android.intent.category.DEFAULT");
//    i.setType("application/fido.uaf_client+json");
//    Bundle data = new Bundle();
//    data.putString("message", authRequest);
//    data.putString("UAFIntentType", "UAF_OPERATION");
//    data.putString("channelBindings", authRequest);
//    i.putExtras(data);
//    startActivityForResult(i, AUTH_RESULT);
  }

  private void findFields() {
    mMsgTextView = (TextView) findViewById(R.id.textViewMsg);
    mTitleTextView = (TextView) findViewById(R.id.textViewTitle);
    mEditTextName = (EditText) findViewById(R.id.editTextName);
    mFacetTextView = (TextView) findViewById(R.id.textViewFacetID);
  }

  private void setSettings(String paramName, String paramValue) {
    SharedPreferences.Editor editor = mPrefs.edit();
    editor.putString(paramName, paramValue);
    editor.apply();
  }

  private void showToast(String msg) {
    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
  }

  private StringBuilder composeExtras(Intent data, int resultCode) {
    Object[] array = Objects.requireNonNull(data.getExtras()).keySet().toArray();
    StringBuilder extras = new StringBuilder();
    extras.append("[resultCode=").append(resultCode).append("]");

    for (Object obj : array) {
      extras.append("[").append(obj).append("=");
      extras.append("").append(data.getExtras().get((String) obj)).append("]");
    }

    return extras;
  }
}
