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

package org.ebayopensource.fidouaf.res.util;

import java.util.HashMap;
import java.util.Map;

import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;

public class StorageImpl implements StorageInterface {

    // Variables

    private static StorageImpl sInstance = new StorageImpl();
    private Map<String, RegistrationRecord> mDB = new HashMap<>();
    private DBConnection mPDB = DBConnection.getInstance();

    // Public

    public static StorageImpl getInstance() {
        return sInstance;
    }

    public void store(RegistrationRecord[] records) throws DuplicateKeyException {
        if (records == null || records.length == 0)
            return;

        for (RegistrationRecord rr : records) {
            if (mPDB.authenticationRecordCount(rr.authenticator))
                throw new DuplicateKeyException();

            mPDB.saveRegistrationRecord(rr);
        }
    }

    public RegistrationRecord readRegistrationRecord(String key) {
        String[] keys = key.split("%%");

        return mPDB.getRecordByKeyAndAAID(keys[1], keys[0]);
    }

    void deleteRegistrationRecord(String key) {
        if (mDB != null && mDB.containsKey(key))
            mDB.remove(key);
    }

    public Map<String, RegistrationRecord> dbDump() {
        return mDB;
    }

    // Private

    private StorageImpl() {}
}
