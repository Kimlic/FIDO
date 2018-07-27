package org.ebayopensource.fidouaf.res.util;

import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DBConnection {

    // Variables

    private static DBConnection sInstance;

    private Connection mConnection;
    private Logger mLgr = Logger.getLogger(DBConnection.class.getName());

    // Public

    public static DBConnection getInstance() {
        if (sInstance == null) {
            String host = getSysEnv("DB_HOST", "localhost");
            String port = getSysEnv("DB_PORT", "5432");
            String user = getSysEnv("DB_USER", "kimlic");
            String dbName = getSysEnv("DB_NAME", "rp_server");
            String password = getSysEnv("DB_PASSWORD", "kimlic");

            sInstance = new DBConnection(host, port, user, dbName, password);
        }

        return sInstance;
    }

    public String version() {
        try (Statement st = mConnection.createStatement(); ResultSet rs = st.executeQuery("SELECT VERSION()")) {
            if (rs.next())
                return rs.getString(1);
            else
                return "Unknown";
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);

            return "Unknown";
        }
    }

    void saveRegistrationRecord(RegistrationRecord rr) {
        try (Statement st = mConnection.createStatement()) {
            rr.authenticator_id = saveAuthenticatorRecord(rr.authenticator);
            st.executeQuery(this.prepareInsertRegistrationRecord(rr));
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    RegistrationRecord getRecordByKeyAndAAID(String key_id, String aaid) {
        try (Statement st = mConnection.createStatement()) {
            ResultSet rs = st.executeQuery(this.prepareGetRecordByKeyAndAAID(key_id, aaid));

            if (!rs.next())
                return null;

            RegistrationRecord regRecord = new RegistrationRecord();
            regRecord.authenticator_id = rs.getString("authenticator_id");
            regRecord.PublicKey = rs.getString("public_key");
            regRecord.SignCounter = rs.getString("sign_counter");
            regRecord.AuthenticatorVersion = rs.getString("authenticator_version");
            regRecord.tcDisplayPNGCharacteristics = rs.getString("tc_display_png_characteristics");
            regRecord.account_address = rs.getString("account_address");
            regRecord.userId = rs.getString("user_id");
            regRecord.deviceId = rs.getString("device_id");
            regRecord.timeStamp = rs.getString("time_stamp");
            regRecord.status = rs.getString("status");
            regRecord.attestCert = rs.getString("attest_cert");
            regRecord.attestDataToSign = rs.getString("attest_data_to_sign");
            regRecord.attestSignature = rs.getString("attest_signature");
            regRecord.attestVerifiedStatus = rs.getString("attest_verified_status");

            return regRecord;
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);
            return null;
        }
    }

//    boolean authenticationRecordCount(AuthenticatorRecord ar) {
//        try (Statement st = mConnection.createStatement()) {
//            String query = prepareAuthenticatorRecord(ar);
//            ResultSet result = st.executeQuery(query);
//
//            if (result.next())
//                return result.getString(1) == null || result.getString(1).isEmpty();
//
//            return false;
//        } catch (SQLException ex) {
//            mLgr.log(Level.SEVERE, ex.getMessage(), ex);
//
//            return false;
//        }
//    }

    int authenticationRecordCount(AuthenticatorRecord ar) {
        try (Statement st = mConnection.createStatement()) {
            ResultSet rs = st.executeQuery(this.prepareAuthenticatorRecord(ar));

            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);
            return 0;
        }

        return 0;
    }

    // Private

    private DBConnection(String host, String port, String user, String dbName, String password) {
        String url = String.format("jdbc:postgresql://%s:%s/%s", host, port, dbName);

        try {
            DriverManager.registerDriver(new org.postgresql.Driver());
            mConnection = DriverManager.getConnection(url, user, password);
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    private static String getSysEnv(String key, String default_value){
        String val = System.getenv(key);

        return (val != null && !val.isEmpty()) ? val : default_value;
    }

    private String prepareAuthenticatorRecord(AuthenticatorRecord ar) {
        return String.format(
                "INSERT INTO rp_uaf.authenticators(\n" +
                        "aaid, key_id, device_id, account_address, status)\n" +
                        "VALUES ('%s', '%s', '%s', '%s', '%s')\n" +
                        "RETURNING ID;",
                ar.AAID, ar.KeyID, ar.deviceId, ar.account_address, ar.status);
    }

    private String prepareInsertRegistrationRecord(RegistrationRecord rr) {
        return String.format(
                "INSERT INTO rp_uaf.registrations(\n" +
                        "authenticator_id, public_key, sign_counter, authenticator_version, \n" +
                        "tc_display_png_characteristics, account_address, user_id, device_id, \n" +
                        "time_stamp, status, attest_cert, attest_data_to_sign, attest_signature, \n" +
                        "attest_verified_status)\n" +
                        "VALUES ('%s', '%s', '%s', '%s', '%s', \n" +
                        "'%s', '%s', '%s', '%s', '%s', \n" +
                        "'%s', '%s', '%s', '%s')\n" +
                        "RETURNING ID;",
                rr.authenticator_id, rr.PublicKey, rr.SignCounter, rr.AuthenticatorVersion, 
                rr.tcDisplayPNGCharacteristics, rr.account_address, rr.userId, rr.deviceId, rr.timeStamp,
                rr.status, rr.attestCert, rr.attestDataToSign, rr.attestSignature, rr.attestVerifiedStatus);
    }

    private String prepareGetRecordByKeyAndAAID(String key, String aaid) {
        return String.format(
                "SELECT r.* " +
                "FROM rp_uaf.registrations AS r " +
                "JOIN rp_uaf.authenticators AS a ON (r.authenticator_id = a.id) " +
                "WHERE a.key_id = '%s' and a.aaid = '%s'" +
                "LIMIT 1;",
                key, aaid
        );
    }

    private String saveAuthenticatorRecord(AuthenticatorRecord ar) {
        try (Statement st = mConnection.createStatement()) {
            ResultSet rs = st.executeQuery(prepareAuthenticatorRecord(ar));

            if (rs.next())
                return rs.getString(1);
            else
                return null;
        } catch (SQLException ex) {
            mLgr.log(Level.SEVERE, ex.getMessage(), ex);

            return null;
        }
    }
}