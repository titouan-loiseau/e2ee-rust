use e2ee_rust_common::{
    crypto::pqkem::keys::IdentifiedPQKEMKeyPair, storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::utils::insert_returning_id;

use super::{consts::REQ_INSERT_IDENTIFIED_PQKEM_KEYPAIR, pqkem_keypair::insert_pqkem_keypair};

pub fn insert_identified_pqkem_keypair(
    key: &IdentifiedPQKEMKeyPair,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the key into the database and return the ID
    let elliptic_curve_keypair_id = insert_pqkem_keypair(&key.key_pair, connection)?;

    Ok(insert_returning_id(
        REQ_INSERT_IDENTIFIED_PQKEM_KEYPAIR,
        params![key.id.as_bytes(), elliptic_curve_keypair_id],
        "identified_pqkem_keypair",
        connection,
    )?)
}
