use e2ee_rust_common::{
    crypto::curve::keys::IdentifiedEllipticCurveKeyPair, storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::utils::insert_returning_id;

use super::{
    consts::REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_KEYPAIR,
    elliptic_curve_keypair::insert_elliptic_curve_keypair,
};

pub fn insert_identified_elliptic_curve_keypair(
    key: &IdentifiedEllipticCurveKeyPair,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the key into the database and return the ID
    let elliptic_curve_keypair_id = insert_elliptic_curve_keypair(&key.key_pair, connection)?;

    Ok(insert_returning_id(
        REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_KEYPAIR,
        params![key.id.as_bytes(), elliptic_curve_keypair_id],
        "identified_elliptic_curve_keypair",
        connection,
    )?)
}
