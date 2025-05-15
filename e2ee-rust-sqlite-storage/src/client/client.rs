use e2ee_rust_common::{
    crypto::{
        curve::keys::{EllipticCurveKeyPair, IdentifiedEllipticCurveKeyPair},
        pqkem::keys::{IdentifiedPQKEMKeyPair, PQKEMKeyPair},
    },
    pqxdh::private_bundle::PrivateBundle,
    storage::{client::errors::ClientStorageError, errors::StorageInterfaceError},
};
use rusqlite::{params, CachedStatement, Connection, Rows};
use uuid::Uuid;

use crate::{
    utils::{insert_returning_id, perform_update, uuid_from_bytes},
    ToStorageInterfaceError,
};

use super::{
    consts::{
        REQ_GET_CLIENT, REQ_GET_CLIENT_UUID, REQ_INSERT_CLIENT, REQ_UPDATE_CLIENT_CURVE_PREKEY,
        REQ_UPDATE_CLIENT_LAST_RESORT_PQKEM_PREKEY,
    },
    one_time_curve_prekey::get_client_one_time_curve_prekey_set,
    one_time_pqkem_prekey::get_client_one_time_pqkem_prekey_set,
};

// Creates a client entry in the database
// The corresponding client private keys must have been added prior and passed to this function
pub fn insert_client(
    client_uuid: &Uuid,
    identity_key_id: i32,
    curve_prekey_id: i32,
    last_resort_prekey_id: i32,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    Ok(insert_returning_id(
        REQ_INSERT_CLIENT,
        params![
            client_uuid.as_bytes(),
            identity_key_id,
            curve_prekey_id,
            last_resort_prekey_id
        ],
        "client",
        connection,
    )?)
}

// Gets the client uuid from the database
pub fn get_client_uuid(connection: &Connection) -> Result<Uuid, StorageInterfaceError> {
    // Prepare the statement
    let mut stmt = connection
        .prepare_cached(REQ_GET_CLIENT_UUID)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = stmt
        .query_map(params![], |row| row.get::<_, Vec<u8>>(0))
        .to_storage_interface_error()?;

    // Get the uuid bytes
    let uuid_bytes = rows
        .next()
        .ok_or(StorageInterfaceError::ClientStorageError(
            ClientStorageError::ClientNotFound,
        ))?
        .to_storage_interface_error()?;

    // Return the uuid
    Ok(uuid_from_bytes(&uuid_bytes)?)
}

// Get the client key bundle from the database
pub fn get_client_key_bundle(
    connection: &Connection,
) -> Result<PrivateBundle, StorageInterfaceError> {
    // Prepare the statement
    let mut stmt: CachedStatement<'_> = connection
        .prepare_cached(REQ_GET_CLIENT)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows: Rows<'_> = stmt.query(params![]).to_storage_interface_error()?;

    // Get the row
    let row: &rusqlite::Row<'_> = rows.next().to_storage_interface_error()?.ok_or(
        StorageInterfaceError::ClientStorageError(ClientStorageError::ClientNotFound),
    )?;

    // Get the values
    let client_db_id: i32 = row.get::<_, i32>(0).to_storage_interface_error()?;
    let identity_key_type: i32 = row.get::<_, i32>(1).to_storage_interface_error()?;
    let identity_key_public: Vec<u8> = row.get::<_, Vec<u8>>(2).to_storage_interface_error()?;
    let identity_key_private: Vec<u8> = row.get::<_, Vec<u8>>(3).to_storage_interface_error()?;
    let curve_prekey_uuid_bytes: Vec<u8> = row.get::<_, Vec<u8>>(4).to_storage_interface_error()?;
    let curve_prekey_type: i32 = row.get::<_, i32>(5).to_storage_interface_error()?;
    let curve_prekey_public: Vec<u8> = row.get::<_, Vec<u8>>(6).to_storage_interface_error()?;
    let curve_prekey_private: Vec<u8> = row.get::<_, Vec<u8>>(7).to_storage_interface_error()?;
    let last_resort_prekey_uuid_bytes: Vec<u8> =
        row.get::<_, Vec<u8>>(8).to_storage_interface_error()?;
    let last_resort_prekey_type: i32 = row.get::<_, i32>(9).to_storage_interface_error()?;
    let last_resort_prekey_public: Vec<u8> =
        row.get::<_, Vec<u8>>(10).to_storage_interface_error()?;
    let last_resort_prekey_private: Vec<u8> =
        row.get::<_, Vec<u8>>(11).to_storage_interface_error()?;

    Ok(PrivateBundle {
        identity_key: EllipticCurveKeyPair::from_bytes(
            identity_key_type as u8,
            identity_key_public,
            identity_key_private,
        )?,
        curve_prekey: IdentifiedEllipticCurveKeyPair {
            id: uuid_from_bytes(&curve_prekey_uuid_bytes)?,
            key_pair: EllipticCurveKeyPair::from_bytes(
                curve_prekey_type as u8,
                curve_prekey_public,
                curve_prekey_private,
            )?,
        },
        last_resort_prekey: IdentifiedPQKEMKeyPair {
            id: uuid_from_bytes(&last_resort_prekey_uuid_bytes)?,
            key_pair: PQKEMKeyPair::from_bytes(
                last_resort_prekey_type as u8,
                last_resort_prekey_public,
                last_resort_prekey_private,
            )?,
        },
        one_time_curve_prekeys: get_client_one_time_curve_prekey_set(client_db_id, connection)?,
        one_time_pqkem_prekeys: get_client_one_time_pqkem_prekey_set(client_db_id, connection)?,
    })
}

pub fn update_client_curve_prekey(
    client_db_id: i32,
    new_signed_prekey_id: i32,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Perform the update
    let rows_modified = perform_update(
        REQ_UPDATE_CLIENT_CURVE_PREKEY,
        params![client_db_id, new_signed_prekey_id],
        connection,
    )?;

    // Check that exactly one row was modified
    if rows_modified != 1 {
        return Err(StorageInterfaceError::ClientStorageError(
            ClientStorageError::ClientNotFound,
        ));
    }

    Ok(())
}

pub fn update_client_last_resort_pqkem_prekey(
    client_db_id: i32,
    new_last_resort_prekey_id: i32,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Perform the update
    let rows_modified = perform_update(
        REQ_UPDATE_CLIENT_LAST_RESORT_PQKEM_PREKEY,
        params![client_db_id, new_last_resort_prekey_id],
        connection,
    )?;

    // Check that exactly one row was modified
    if rows_modified != 1 {
        return Err(StorageInterfaceError::ClientStorageError(
            ClientStorageError::ClientNotFound,
        ));
    }

    Ok(())
}
