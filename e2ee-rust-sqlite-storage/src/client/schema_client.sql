-- Schema version
PRAGMA user_version = 1;

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Create the Elliptic Curve Keypair table
CREATE TABLE IF NOT EXISTS elliptic_curve_keypair (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);

-- Create the PQKEM Keypair table
CREATE TABLE IF NOT EXISTS pqkem_keypair (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);

-- Create the Identified Elliptic Curve Keypair table
CREATE TABLE IF NOT EXISTS identified_elliptic_curve_keypair (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    elliptic_curve_keypair_id INTEGER NOT NULL,
    FOREIGN KEY (elliptic_curve_keypair_id) REFERENCES elliptic_curve_keypair(id)
);

-- Create the Identified PQKEM Keypair table
CREATE TABLE IF NOT EXISTS identified_pqkem_keypair (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    pqkem_keypair_id INTEGER NOT NULL,
    FOREIGN KEY (pqkem_keypair_id) REFERENCES pqkem_keypair(id)
);

-- Create the Client table
CREATE TABLE IF NOT EXISTS client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid BLOB NOT NULL UNIQUE,
    identity_key_id INTEGER NOT NULL,
    curve_prekey_id INTEGER NOT NULL,
    last_resort_prekey_id INTEGER NOT NULL,
    FOREIGN KEY (identity_key_id) REFERENCES elliptic_curve_keypair(id),
    FOREIGN KEY (curve_prekey_id) REFERENCES identified_elliptic_curve_keypair(id),
    FOREIGN KEY (last_resort_prekey_id) REFERENCES identified_pqkem_keypair(id)
);

-- Create the One-Time Curve Prekey table
CREATE TABLE IF NOT EXISTS one_time_curve_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    identified_elliptic_curve_keypair_id INTEGER NOT NULL,
    FOREIGN KEY (client_id) REFERENCES client(id),
    FOREIGN KEY (identified_elliptic_curve_keypair_id) REFERENCES identified_elliptic_curve_keypair(id)
);

-- Create the One-Time PQKEM Prekey table
CREATE TABLE IF NOT EXISTS one_time_pqkem_prekey (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    identified_pqkem_keypair_id INTEGER NOT NULL,
    FOREIGN KEY (client_id) REFERENCES client(id),
    FOREIGN KEY (identified_pqkem_keypair_id) REFERENCES identified_pqkem_keypair(id)
);