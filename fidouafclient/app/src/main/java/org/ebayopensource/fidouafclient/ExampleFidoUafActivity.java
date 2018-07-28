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

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.op.Auth;
import org.ebayopensource.fido.uaf.client.op.Reg;
import org.ebayopensource.fido.uaf.crypto.FidoKeystoreAndroidM;
import org.ebayopensource.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.fido.uaf.crypto.FidoSignerAndroidM;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthProcessor;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthenticationDialogFragment;
import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Objects;

public class ExampleFidoUafActivity extends Activity implements FingerprintAuthProcessor {

  // Constants

  @SuppressWarnings("unused")
  private static final String LOG_TAG = ExampleFidoUafActivity.class.getSimpleName();
  private static final String DIALOG_FRAGMENT_FINGERPRINT = "DIALOG_FRAGMENT_FINGERPRINT";
  private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

  // Variables

  private Gson gson = new Gson();
  private Auth authOp;
  private KeyguardManager keyguardManager;
  private String authReq;
  private FidoKeystoreAndroidM fidoKeystore;

  // Life

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_fido_uaf);

    fidoKeystore = FidoKeystoreAndroidM.createKeyStore(this);
    keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
    authOp = new Auth(this);

    Bundle extras = this.getIntent().getExtras();
    TextView operation = findViewById(R.id.textViewOperation);
    TextView uafMsg = findViewById(R.id.textViewOpMsg);
    operation.setText(Objects.requireNonNull(extras).getString("UAFIntentType"));
    uafMsg.setText(extras.getString("message"));
  }

  // Actions

  public void proceedAction(View view) {
    if (isAuthOp() && supportsFingerprintAuth()) {
      processOpAndFinish();
    } else {
      confirmDeviceCredential();
    }
  }

  // FingerprintAuthProcessor

  @Override
  public void processAuthentication(FingerprintManager.CryptoObject cryptObj) {
    FidoSigner fidoSigner = new FidoSignerAndroidM(cryptObj.getSignature());
    String msg = authOp.auth(authReq, fidoSigner, null);

    returnResultAndFinish(msg);
  }

  // Private

  private void processOpAndFinish() {
    String inMsg = intentMessage();
    String accountAddress = intentAccountAddress();

    if (inMsg != null && inMsg.length() > 0)
      processOp(inMsg, accountAddress);
  }

  private void finishWithError(String errorMessage) {
    Bundle data = new Bundle();
    data.putString("message", errorMessage);

    Intent intent = new Intent();
    intent.putExtras(data);
    setResult(RESULT_CANCELED, intent);
    finish();
  }

  private void opRegResponse(String inMsg) {
    RegistrationRequest regRequest = gson.fromJson(inMsg, RegistrationRequest[].class)[0];
    Log.e(LOG_TAG, "AAAAAAA: " + intentAccountAddress() + ",      REGREQ: " + regRequest.accountAddress);
    String msg = Reg.register(inMsg, intentAccountAddress(), fidoKeystore, this);

    returnResultAndFinish(msg);
  }

  private void opAuthResponse(String inMsg, String accountAddress) throws GeneralSecurityException {
    authReq = inMsg;

    if (supportsFingerprintAuth()) {
      startFingerprintAuth(accountAddress);
    } else {
      FidoSigner fidoSigner = createFidoSigner(accountAddress);
      String authMsg = authOp.auth(authReq, fidoSigner, null);

      returnResultAndFinish(authMsg);
    }
  }

  private void processOp(String inUafOperationMsg, String accountAddress) {
    try {
      final String inMsg = extract(inUafOperationMsg);

      if (inMsg.contains("\"Reg\""))
        opRegResponse(inMsg);
      else if (inMsg.contains("\"Auth\""))
        opAuthResponse(inMsg, accountAddress);
      else if (inMsg.contains("\"Dereg\"")) {
        returnResultAndFinish(inUafOperationMsg);
      }
    } catch (GeneralSecurityException | SecurityException e) {
      finishWithError("Error : " + e.getMessage());
    }
  }

  @NonNull
  private FidoSigner createFidoSigner(String accountAddress) throws NoSuchAlgorithmException, InvalidKeyException {
    Signature signature = Signature.getInstance("SHA256withECDSA");
    PrivateKey privateKey = fidoKeystore.getKeyPair(accountAddress).getPrivate();
    signature.initSign(privateKey);

    return new FidoSignerAndroidM(signature);
  }

  private void startFingerprintAuth(String accountAddress) throws GeneralSecurityException {
    Signature signature = Signature.getInstance("SHA256withECDSA");
    PrivateKey privateKey = fidoKeystore.getKeyPair(accountAddress).getPrivate();
    signature.initSign(privateKey);

    FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
    FingerprintManager.CryptoObject cryptoObj = new FingerprintManager.CryptoObject(signature);
    fragment.setCryptoObject(cryptoObj);
    fragment.setStage(FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
    fragment.show(getFragmentManager(), DIALOG_FRAGMENT_FINGERPRINT);
  }

  private void returnResultAndFinish(String msg) {
    Bundle data = new Bundle();
    data.putString("message", msg);
    Intent intent = new Intent();
    intent.putExtras(data);
    setResult(RESULT_OK, intent);
    finish();
  }

  private boolean supportsFingerprintAuth() {
    FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

    return Objects.requireNonNull(fingerprintManager).isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints();
  }

  private boolean isAuthOp() {
    String msg = Objects.requireNonNull(getIntent().getExtras()).getString("message");

    return extract(msg).contains("\"Auth\"");
  }

  private void confirmDeviceCredential() {
    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("UAF", "Confirm Identity");

    if (intent != null) {
      startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
    } else {
      finishWithError("Unable to complete local authentication, please setup android device authentication(pin, pattern, fingerprint..)");
    }
  }

  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (requestCode != REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS)
      return;

    if (resultCode == RESULT_OK) {
      processOpAndFinish();
    } else {
      finishWithError("User cancelled credential verification");
    }
  }

  public void back(View view) {
    Bundle data = new Bundle();
    data.putString("message", "");

    Intent intent = new Intent();
    intent.putExtras(data);
    setResult(RESULT_OK, intent);

    finish();
  }

  private String extract(String inMsg) {
    try {
      JSONObject tmpJson = new JSONObject(inMsg);
      String uafMsg = tmpJson.getString("uafProtocolMessage");
      uafMsg = uafMsg.replace("\\\"", "\"");

      return uafMsg;
    } catch (Exception e) {
      return "";
    }
  }

  private Bundle intentExtras() {
    return Objects.requireNonNull(getIntent().getExtras());
  }

  private String intentMessage() {
    return intentExtras().getString("message");
  }

  private String intentAccountAddress() {
    return intentExtras().getString("accountAddress");
  }
}
