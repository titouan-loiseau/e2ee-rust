use e2ee_rust_common::{
    crypto::curve::keys::EllipticCurvePublicKey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{utils::insert_returning_id, ToStorageInterfaceError};

use super::consts::{REQ_INSERT_ELLIPTIC_CURVE_PUBLIC_KEY, REQ_QUERY_ELLIPTIC_CURVE_PUBLIC_KEY};

pub fn get_elliptic_curve_public_key(
    key_id: i32,
    connection: &Connection,
) -> Result<EllipticCurvePublicKey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_ELLIPTIC_CURVE_PUBLIC_KEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement.query([key_id]).to_storage_interface_error()?;

    // Get the row
    if let Some(row) = rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(
            ServerStorageError::EllipticCurvePublicKeyNotFound,
        )
    })? {
        // Get the fields
        let key_type: i32 = row.get(0).to_storage_interface_error()?;
        let identity_key_bytes: Vec<u8> = row.get(1).to_storage_interface_error()?;

        Ok(EllipticCurvePublicKey::from_bytes(
            key_type as u8,
            identity_key_bytes,
        )?)
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::EllipticCurvePublicKeyNotFound,
        ));
    }
}

pub fn insert_elliptic_curve_public_key(
    key: &EllipticCurvePublicKey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_ELLIPTIC_CURVE_PUBLIC_KEY,
        params![key.key_type.id(), key.bytes.as_slice()],
        "elliptic_curve_public_key",
        connection,
    )?)
}
