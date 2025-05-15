use e2ee_rust_common::{
    pqxdh::signed_pqkem_prekey::SignedPQKEMPrekey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{utils::insert_returning_id, ToStorageInterfaceError};

use super::{
    consts::{REQ_INSERT_SIGNED_PQKEM_PREKEY, REQ_QUERY_SIGNED_PQKEM_PREKEY},
    identified_pqkem_public_key::{
        get_identified_pqkem_public_key, insert_identified_pqkem_public_key,
    },
};

pub fn get_signed_pqkem_prekey(
    id: i32,
    connection: &Connection,
) -> Result<SignedPQKEMPrekey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_SIGNED_PQKEM_PREKEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement.query([id]).to_storage_interface_error()?;

    // Get the row
    if let Some(row) = rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(ServerStorageError::SignedPQKEMPrekeyNotFound)
    })? {
        // Get the fields from the row
        let identified_public_key_id: i32 = row.get(0).to_storage_interface_error()?;
        let signature: Vec<u8> = row.get(1).to_storage_interface_error()?;

        // Get the identified pqkem public key
        let identified_public_key =
            get_identified_pqkem_public_key(identified_public_key_id, connection)?;

        Ok(SignedPQKEMPrekey {
            identified_public_key,
            signature: signature
                .try_into()
                .map_err(|_| StorageInterfaceError::BadSignature)?,
        })
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::SignedPQKEMPrekeyNotFound,
        ));
    }
}

pub fn insert_signed_pqkem_prekey(
    key: &SignedPQKEMPrekey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the identified PQKEM public key
    let identified_pqkem_public_key_id =
        insert_identified_pqkem_public_key(&key.identified_public_key, connection)?;

    // Insert the signed PQKEM prekey and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_SIGNED_PQKEM_PREKEY,
        params![identified_pqkem_public_key_id, &key.signature],
        "signed_pqkem_prekey",
        connection,
    )?)
}
