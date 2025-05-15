use e2ee_rust_common::{
    crypto::pqkem::keys::IdentifiedPQKEMPublicKey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{
    utils::{insert_returning_id, uuid_from_bytes},
    ToStorageInterfaceError,
};

use super::{
    consts::{REQ_INSERT_IDENTIFIED_PQKEM_PUBLIC_KEY, REQ_QUERY_IDENTIFIED_PQKEM_PUBLIC_KEY},
    pqkem_public_key::{get_pqkem_public_key, insert_pqkem_public_key},
};

pub fn get_identified_pqkem_public_key(
    db_key_id: i32,
    connection: &Connection,
) -> Result<IdentifiedPQKEMPublicKey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_IDENTIFIED_PQKEM_PUBLIC_KEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement.query([db_key_id]).to_storage_interface_error()?;

    // Get the row
    if let Some(row) = rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(
            ServerStorageError::IdentifiedPQKEMPublicKeyNotFound,
        )
    })? {
        // Get the fields
        let uuid: Vec<u8> = row.get(0).to_storage_interface_error()?;
        let pqkem_public_key_id: i32 = row.get(1).to_storage_interface_error()?;

        // Get the pqkem public key
        let pqkem_public_key = get_pqkem_public_key(pqkem_public_key_id, connection)?;

        Ok(IdentifiedPQKEMPublicKey {
            id: uuid_from_bytes(&uuid)?,
            public_key: pqkem_public_key,
        })
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::IdentifiedPQKEMPublicKeyNotFound,
        ));
    }
}

pub fn insert_identified_pqkem_public_key(
    key: &IdentifiedPQKEMPublicKey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the PQKEM public key
    let pqkem_public_key_id = insert_pqkem_public_key(&key.public_key, connection)?;

    // Insert the identified PQKEM public key and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_IDENTIFIED_PQKEM_PUBLIC_KEY,
        params![key.id.as_bytes(), pqkem_public_key_id],
        "identified_pqkem_public_key",
        connection,
    )?)
}
