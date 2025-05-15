-- Schema version
PRAGMA user_version = 1;

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Create the Elliptic Curve Public Key table
CREATE TABLE IF NOT EXISTS elliptic_curve_public_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type INTEGER NOT NULL,
    public_key BLOB NOT NULL
);

-- Create the PQKEM Public Key table
CREATE TABLE IF NOT EXISTS pqkem_public_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type INTEGER NOT NULL,
    public_key BLOB NOT NULL
);

-- Create the Identified Elliptic Curve Public Key table
CREATE TABLE IF NOT EXISTS identified_elliptic_curve_public_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    elliptic_curve_public_key_id INTEGER NOT NULL,
    FOREIGN KEY (elliptic_curve_public_key_id) REFERENCES elliptic_curve_public_key(id)
);

-- Create the Identified PQKEM Public Key table
CREATE TABLE IF NOT EXISTS identified_pqkem_public_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    pqkem_public_key_id INTEGER NOT NULL,
    FOREIGN KEY (pqkem_public_key_id) REFERENCES pqkem_public_key(id)
);

-- Create the Signed Curve Prekey table
CREATE TABLE IF NOT EXISTS signed_curve_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identified_public_key_id INTEGER NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (identified_public_key_id) REFERENCES identified_elliptic_curve_public_key(id)
);

-- Create the Signed PQKEM Prekey table
CREATE TABLE IF NOT EXISTS signed_pqkem_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identified_public_key_id INTEGER NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY (identified_public_key_id) REFERENCES identified_pqkem_public_key(id)
);

-- Create the key bundles table
CREATE TABLE IF NOT EXISTS key_bundle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_key_id INTEGER NOT NULL,
    identity_key_timestamp INTEGER NOT NULL,
    signed_curve_prekey_id INTEGER NOT NULL,
    signed_curve_prekey_timestamp INTEGER NOT NULL,
    signed_last_resort_pqkem_prekey_id INTEGER NOT NULL,
    signed_last_resort_pqkem_prekey_timestamp INTEGER NOT NULL,
    FOREIGN KEY (identity_key_id) REFERENCES elliptic_curve_public_key(id),
    FOREIGN KEY (signed_curve_prekey_id) REFERENCES signed_curve_prekey(id),
    FOREIGN KEY (signed_last_resort_pqkem_prekey_id) REFERENCES signed_pqkem_prekey(id)
);

-- Create the One-Time Curve Prekey table
CREATE TABLE IF NOT EXISTS one_time_curve_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prekey_id INTEGER NOT NULL,
    key_bundle_id INTEGER NOT NULL,
    FOREIGN KEY (prekey_id) REFERENCES identified_elliptic_curve_public_key(id),
    FOREIGN KEY (key_bundle_id) REFERENCES key_bundle(id)
);

-- Create the Signed One-Time PQKEM Prekey table
CREATE TABLE IF NOT EXISTS signed_one_time_pqkem_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    --
    prekey_id INTEGER NOT NULL,
    key_bundle_id INTEGER NOT NULL,
    FOREIGN KEY (prekey_id) REFERENCES signed_pqkem_prekey(id),
    FOREIGN KEY (key_bundle_id) REFERENCES key_bundle(id)
);

-- Create the clients table
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_uuid BLOB NOT NULL UNIQUE,
    client_key_bundle_id INTEGER NOT NULL,
    FOREIGN KEY (client_key_bundle_id) REFERENCES key_bundle(id)
);