use e2ee_rust_common::{
    crypto::curve::keys::EllipticCurveKeyPair, storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::utils::insert_returning_id;

use super::consts::REQ_INSERT_ELLIPTIC_CURVE_KEYPAIR;

pub fn insert_elliptic_curve_keypair(
    key: &EllipticCurveKeyPair,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    Ok(insert_returning_id(
        REQ_INSERT_ELLIPTIC_CURVE_KEYPAIR,
        params![
            key.key_type.id(),
            key.public_key.bytes,
            key.private_key.bytes
        ],
        "elliptic_curve_keypair",
        connection,
    )?)
}
