use e2ee_rust_common::{
    crypto::pqkem::keys::{IdentifiedPQKEMKeyPair, PQKEMKeyPair},
    storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::{
    utils::{insert_returning_id, uuid_from_bytes},
    ToStorageInterfaceError,
};

use super::{
    consts::{REQ_GET_CLIENT_ONE_TIME_PQKEM_PREKEY, REQ_INSERT_ONE_TIME_PQKEM_PREKEY},
    identified_pqkem_keypair::insert_identified_pqkem_keypair,
};

pub fn insert_one_time_pqkem_prekey(
    client_db_id: i32,
    identified_pqkem_keypair_id: i32,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    Ok(insert_returning_id(
        REQ_INSERT_ONE_TIME_PQKEM_PREKEY,
        params![client_db_id, identified_pqkem_keypair_id],
        "one_time_pqkem_prekey",
        connection,
    )?)
}

pub fn insert_one_time_pqkem_prekey_set(
    client_db_id: i32,
    one_time_pqkem_prekeys: &[IdentifiedPQKEMKeyPair],
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Loop through the one-time PQKEM prekeys
    for prekey in one_time_pqkem_prekeys {
        // Insert the one-time PQKEM prekey
        let prekey_id = insert_identified_pqkem_keypair(prekey, connection)?;

        // Insert the one-time PQKEM prekey
        insert_one_time_pqkem_prekey(client_db_id, prekey_id, connection)?;
    }
    Ok(())
}

pub fn get_client_one_time_pqkem_prekey_set(
    client_db_id: i32,
    connection: &Connection,
) -> Result<Vec<IdentifiedPQKEMKeyPair>, StorageInterfaceError> {
    // Prepare the statement
    let mut stmt = connection
        .prepare_cached(REQ_GET_CLIENT_ONE_TIME_PQKEM_PREKEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = stmt
        .query(params![client_db_id])
        .to_storage_interface_error()?;

    // Loop through the rows
    let mut one_time_pqkem_prekeys = Vec::new();
    while let Some(row) = rows.next().to_storage_interface_error()? {
        // Get the values
        let identified_pqkem_key_uuid: Vec<u8> = row.get(0).to_storage_interface_error()?;
        let pqkem_keytype: i32 = row.get(1).to_storage_interface_error()?;
        let pqkem_public_key: Vec<u8> = row.get(2).to_storage_interface_error()?;
        let pqkem_private_key: Vec<u8> = row.get(3).to_storage_interface_error()?;

        // Create the identified PQKEM keypair
        let identified_pqkem_keypair = IdentifiedPQKEMKeyPair {
            id: uuid_from_bytes(&identified_pqkem_key_uuid)?,
            key_pair: PQKEMKeyPair::from_bytes(
                pqkem_keytype as u8,
                pqkem_public_key,
                pqkem_private_key,
            )?,
        };

        // Add the one time PQKEM prekey to the vector
        one_time_pqkem_prekeys.push(identified_pqkem_keypair);
    }

    // Return the one time PQKEM prekeys
    Ok(one_time_pqkem_prekeys)
}
