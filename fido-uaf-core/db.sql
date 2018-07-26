CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE authenticators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aaid varchar(256),
    key_id varchar(256),
    device_id varchar(256),
    username varchar(256),
    status varchar(256)
);

CREATE TABLE registrations (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     authenticator_id UUID references authenticators (id),
     public_key varchar(256),
     sign_counter varchar(256),
     authenticator_version varchar(256),
     tc_display_png_characteristics varchar(256),
     username varchar(256),
     user_id varchar(256),
     device_id varchar(256),
     time_stamp varchar(256),
     status varchar(256),
     attest_cert varchar(1024),
     attest_data_to_sign varchar(256),
     attest_signature varchar(256),
     attest_verified_status varchar(256))
К