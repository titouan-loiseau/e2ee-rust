use e2ee_rust_common::{crypto::pqkem::keys::PQKEMKeyPair, storage::errors::StorageInterfaceError};
use rusqlite::{params, Connection};

use crate::utils::insert_returning_id;

use super::consts::REQ_INSERT_PQKEM_KEYPAIR;

pub fn insert_pqkem_keypair(
    key: &PQKEMKeyPair,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    Ok(insert_returning_id(
        REQ_INSERT_PQKEM_KEYPAIR,
        params![
            key.key_type.id(),
            key.public_key.bytes,
            key.private_key.bytes
        ],
        "pqkem_keypair",
        connection,
    )?)
}
