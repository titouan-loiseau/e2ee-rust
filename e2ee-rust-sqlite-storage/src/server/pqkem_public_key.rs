use e2ee_rust_common::{
    crypto::pqkem::keys::PQKEMPublicKey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{
    server::consts::REQ_DELETE_PQKEM_PUBLIC_KEY,
    utils::{insert_returning_id, perform_delete},
    ToStorageInterfaceError,
};

use super::consts::{REQ_INSERT_PQKEM_PUBLIC_KEY, REQ_QUERY_PQKEM_PUBLIC_KEY};

pub fn get_pqkem_public_key(
    key_id: i32,
    connection: &Connection,
) -> Result<PQKEMPublicKey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_PQKEM_PUBLIC_KEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement.query([key_id]).to_storage_interface_error()?;

    // Get the row
    if let Some(row) = rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(ServerStorageError::PQKEMPublicKeyNotFound)
    })? {
        // Get the fields
        let key_type: i32 = row.get(0).to_storage_interface_error()?;
        let identity_key_bytes: Vec<u8> = row.get(1).to_storage_interface_error()?;

        Ok(PQKEMPublicKey::from_bytes(
            key_type as u8,
            identity_key_bytes,
        )?)
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::PQKEMPublicKeyNotFound,
        ));
    }
}

pub fn insert_pqkem_public_key(
    key: &PQKEMPublicKey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the PQKEM public key and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_PQKEM_PUBLIC_KEY,
        params![key.key_type.id(), key.bytes.as_slice()],
        "pqkem_public_key",
        connection,
    )?)
}

pub fn delete_pqkem_public_key(
    db_key_id: i32,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    perform_delete(REQ_DELETE_PQKEM_PUBLIC_KEY, params![db_key_id], connection)
}
