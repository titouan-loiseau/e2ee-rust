pub const REQ_FIND_TABLES: &str = "SELECT name FROM sqlite_master WHERE type='table'";

pub const REQ_INSERT_CLIENT: &str =
    "INSERT INTO clients (client_uuid, client_key_bundle_id) VALUES (?1, ?2) RETURNING id";

pub const REQ_GET_KEY_BUNDLE_ID: &str =
    "SELECT client_key_bundle_id FROM clients WHERE client_uuid = ?1";
pub const REQ_QUERY_KEY_BUNDLE: &str = "SELECT identity_key_id, identity_key_timestamp, signed_curve_prekey_id, signed_curve_prekey_timestamp, signed_last_resort_pqkem_prekey_id, signed_last_resort_pqkem_prekey_timestamp FROM key_bundle WHERE id = ?1";
pub const REQ_INSERT_KEY_BUNDLE: &str = "INSERT INTO key_bundle (identity_key_id, identity_key_timestamp, signed_curve_prekey_id, signed_curve_prekey_timestamp, signed_last_resort_pqkem_prekey_id, signed_last_resort_pqkem_prekey_timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id";

// KEY_BUNDLE UPDATES
pub const REQ_UPDATE_KEY_BUNDLE_SIGNED_CURVE_PREKEY: &str = "UPDATE key_bundle SET signed_curve_prekey_id = ?2, signed_curve_prekey_timestamp = ?3 WHERE id = ?1";
pub const REQ_UPDATE_KEY_BUNDLE_SIGNED_LAST_RESORT_PQKEM_PREKEY: &str = "UPDATE key_bundle SET signed_last_resort_pqkem_prekey_id = ?2, signed_last_resort_pqkem_prekey_timestamp = ?3 WHERE id = ?1";

pub const REQ_QUERY_ELLIPTIC_CURVE_PUBLIC_KEY: &str =
    "SELECT key_type, public_key FROM elliptic_curve_public_key WHERE id = ?1";
pub const REQ_INSERT_ELLIPTIC_CURVE_PUBLIC_KEY: &str =
    "INSERT INTO elliptic_curve_public_key (key_type, public_key) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_ELLIPTIC_CURVE_PUBLIC_KEY: &str =
    "DELETE FROM elliptic_curve_public_key WHERE id = ?1";

pub const REQ_QUERY_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY: &str = "SELECT uuid, elliptic_curve_public_key_id FROM identified_elliptic_curve_public_key WHERE id = ?1";
pub const REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY: &str = "INSERT INTO identified_elliptic_curve_public_key (uuid, elliptic_curve_public_key_id) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY: &str =
    "DELETE FROM identified_elliptic_curve_public_key WHERE id = ?1";

pub const REQ_QUERY_SIGNED_CURVE_PREKEY: &str =
    "SELECT identified_public_key_id, signature FROM signed_curve_prekey WHERE id = ?1";
pub const REQ_INSERT_SIGNED_CURVE_PREKEY: &str = "INSERT INTO signed_curve_prekey (identified_public_key_id, signature) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_SIGNED_CURVE_PREKEY: &str = "DELETE FROM signed_curve_prekey WHERE id = ?1";

pub const REQ_QUERY_PQKEM_PUBLIC_KEY: &str =
    "SELECT key_type, public_key FROM pqkem_public_key WHERE id = ?1";
pub const REQ_INSERT_PQKEM_PUBLIC_KEY: &str =
    "INSERT INTO pqkem_public_key (key_type, public_key) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_PQKEM_PUBLIC_KEY: &str = "DELETE FROM pqkem_public_key WHERE id = ?1";

pub const REQ_QUERY_IDENTIFIED_PQKEM_PUBLIC_KEY: &str =
    "SELECT uuid, pqkem_public_key_id FROM identified_pqkem_public_key WHERE id = ?1";
pub const REQ_INSERT_IDENTIFIED_PQKEM_PUBLIC_KEY: &str = "INSERT INTO identified_pqkem_public_key (uuid, pqkem_public_key_id) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_IDENTIFIED_PQKEM_PUBLIC_KEY: &str =
    "DELETE FROM identified_pqkem_public_key WHERE id = ?1";

pub const REQ_QUERY_SIGNED_PQKEM_PREKEY: &str =
    "SELECT identified_public_key_id, signature FROM signed_pqkem_prekey WHERE id = ?1";
pub const REQ_INSERT_SIGNED_PQKEM_PREKEY: &str = "INSERT INTO signed_pqkem_prekey (identified_public_key_id, signature) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_SIGNED_PQKEM_PREKEY: &str = "DELETE FROM signed_pqkem_prekey WHERE id = ?1";

pub const REQ_QUERY_ONE_TIME_CURVE_PREKEY_SET: &str =
    "SELECT prekey_id, id FROM one_time_curve_prekey WHERE key_bundle_id = ?1";
pub const REQ_INSERT_ONE_TIME_CURVE_PREKEY: &str =
    "INSERT INTO one_time_curve_prekey (prekey_id, key_bundle_id) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_ONE_TIME_CURVE_PREKEY: &str =
    "DELETE FROM one_time_curve_prekey WHERE id = ?1";

pub const REQ_QUERY_SIGNED_ONE_TIME_PQKEM_PREKEY_SET: &str =
    "SELECT prekey_id, id FROM signed_one_time_pqkem_prekey WHERE key_bundle_id = ?1";
pub const REQ_INSERT_SIGNED_ONE_TIME_PQKEM_PREKEY: &str = "INSERT INTO signed_one_time_pqkem_prekey (prekey_id, key_bundle_id) VALUES (?1, ?2) RETURNING id";
pub const REQ_DELETE_SIGNED_ONE_TIME_PQKEM_PREKEY: &str =
    "DELETE FROM signed_one_time_pqkem_prekey WHERE id = ?1";
