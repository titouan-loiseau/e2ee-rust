use chrono::{DateTime, Utc};
use e2ee_rust_common::storage::{
    errors::StorageInterfaceError,
    server::{client_structs::ClientKeyBundle, errors::ServerStorageError},
};
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::{
    utils::{datetime_to_timestamp, insert_returning_id, perform_update, timestamp_to_datetime},
    ToStorageInterfaceError,
};

use super::{
    consts::{
        REQ_GET_KEY_BUNDLE_ID, REQ_INSERT_KEY_BUNDLE, REQ_QUERY_KEY_BUNDLE,
        REQ_UPDATE_KEY_BUNDLE_SIGNED_CURVE_PREKEY,
        REQ_UPDATE_KEY_BUNDLE_SIGNED_LAST_RESORT_PQKEM_PREKEY,
    },
    elliptic_curve_public_key::{get_elliptic_curve_public_key, insert_elliptic_curve_public_key},
    one_time_curve_prekey::{get_one_time_curve_prekey_set, insert_one_time_curve_prekey_set},
    signed_curve_prekey::{get_signed_curve_prekey, insert_signed_curve_prekey},
    signed_one_time_pqkem_prekey::{
        get_signed_one_time_pqkem_prekey_set, insert_signed_one_time_pqkem_prekey_set,
    },
    signed_pqkem_prekey::{get_signed_pqkem_prekey, insert_signed_pqkem_prekey},
};

pub fn get_client_key_bundle_id(
    client_id: Uuid,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Create the statement
    let mut stmt = connection
        .prepare_cached(REQ_GET_KEY_BUNDLE_ID)
        .to_storage_interface_error()?;

    // Execute the statement and get the result
    let mut rows = stmt
        .query([client_id.as_bytes()])
        .to_storage_interface_error()?;
    if let Some(row) = rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(ServerStorageError::ClientNotFound)
    })? {
        // Get the key bundle id from the row
        Ok(row.get(0).to_storage_interface_error()?)
    } else {
        Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::ClientNotFound,
        ))?
    }
}

pub fn get_key_bundle_from_id(
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<ClientKeyBundle, StorageInterfaceError> {
    // Get all the single key information from the key_bundle table
    let (
        identity_key_id,
        identity_key_timestamp,
        signed_curve_prekey_id,
        signed_curve_prekey_timestamp,
        signed_last_resort_pqkem_prekey_id,
        signed_last_resort_pqkem_prekey_timestamp,
    ) = {
        // Create the statement
        let mut key_bundle_stmt = connection
            .prepare_cached(REQ_QUERY_KEY_BUNDLE)
            .to_storage_interface_error()?;
        let mut key_bundle_rows = key_bundle_stmt
            .query([key_bundle_id])
            .to_storage_interface_error()?;
        if let Some(key_bundle_row) = key_bundle_rows.next().map_err(|_| {
            StorageInterfaceError::ServerStorageError(ServerStorageError::KeyBundleNotFound)
        })? {
            // Get the key bundle from the row
            let identity_key_id: i32 = key_bundle_row.get(0).to_storage_interface_error()?;
            let identity_key_timestamp: i64 = key_bundle_row.get(1).to_storage_interface_error()?;
            let signed_curve_prekey_id: i32 = key_bundle_row.get(2).to_storage_interface_error()?;
            let signed_curve_prekey_timestamp: i64 =
                key_bundle_row.get(3).to_storage_interface_error()?;
            let signed_last_resort_pqkem_prekey_id: i32 =
                key_bundle_row.get(4).to_storage_interface_error()?;
            let signed_last_resort_pqkem_prekey_timestamp: i64 =
                key_bundle_row.get(5).to_storage_interface_error()?;
            (
                identity_key_id,
                identity_key_timestamp,
                signed_curve_prekey_id,
                signed_curve_prekey_timestamp,
                signed_last_resort_pqkem_prekey_id,
                signed_last_resort_pqkem_prekey_timestamp,
            )
        } else {
            Err(StorageInterfaceError::ServerStorageError(
                ServerStorageError::KeyBundleNotFound,
            ))?
        }
    };

    // Get the identity key from the elliptic_curve_public_key table
    let identity_key = get_elliptic_curve_public_key(identity_key_id, connection)?;
    let identity_key_timestamp = timestamp_to_datetime(identity_key_timestamp)?;

    // Get the signed curve prekey from the signed_curve_prekey table
    let signed_curve_prekey = get_signed_curve_prekey(signed_curve_prekey_id, connection)?;
    let signed_curve_prekey_timestamp = timestamp_to_datetime(signed_curve_prekey_timestamp)?;

    // Get the signed last resort PQKEM prekey from the signed_pqkem_prekey table
    let signed_last_resort_pqkem_prekey =
        get_signed_pqkem_prekey(signed_last_resort_pqkem_prekey_id, connection)?;
    let signed_last_resort_pqkem_prekey_timestamp =
        timestamp_to_datetime(signed_last_resort_pqkem_prekey_timestamp)?;

    // Get the one time curve prekey set from the one_time_curve_prekey_set table
    let one_time_curve_prekey_set = get_one_time_curve_prekey_set(key_bundle_id, connection)?;

    // Get the signed one time PQKEM prekey set from the signed_one_time_pqkem_prekey_set table
    let signed_one_time_pqkem_prekey_set =
        get_signed_one_time_pqkem_prekey_set(key_bundle_id, connection)?;

    Ok(ClientKeyBundle {
        identity_key: (identity_key, identity_key_timestamp),
        signed_curve_prekey: (signed_curve_prekey, signed_curve_prekey_timestamp),
        signed_last_resort_pqkem_prekey: (
            signed_last_resort_pqkem_prekey,
            signed_last_resort_pqkem_prekey_timestamp,
        ),
        one_time_curve_prekeys: one_time_curve_prekey_set,
        signed_one_time_pqkem_prekeys: signed_one_time_pqkem_prekey_set,
    })
}

pub fn get_signed_curve_prekey_id(
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Create the statement
    let mut key_bundle_stmt = connection
        .prepare_cached(REQ_QUERY_KEY_BUNDLE)
        .to_storage_interface_error()?;

    // Execute statement
    let mut key_bundle_rows = key_bundle_stmt
        .query([key_bundle_id])
        .to_storage_interface_error()?;

    // Get the row
    let row = key_bundle_rows.next().to_storage_interface_error()?.ok_or(
        StorageInterfaceError::ServerStorageError(ServerStorageError::KeyBundleNotFound),
    )?;

    // Return the curve ID
    Ok(row.get(2).to_storage_interface_error()?)
}

pub fn get_signed_last_resort_pqkem_prekey_id(
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Create the statement
    let mut key_bundle_stmt = connection
        .prepare_cached(REQ_QUERY_KEY_BUNDLE)
        .to_storage_interface_error()?;

    // Execute statement
    let mut key_bundle_rows = key_bundle_stmt
        .query([key_bundle_id])
        .to_storage_interface_error()?;

    // Get the row
    let row = key_bundle_rows.next().to_storage_interface_error()?.ok_or(
        StorageInterfaceError::ServerStorageError(ServerStorageError::KeyBundleNotFound),
    )?;

    // Return the signed last resort pqkem prekey ID
    Ok(row.get(4).to_storage_interface_error()?)
}

pub fn insert_key_bundle(
    key_bundle: &ClientKeyBundle,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the identity key into the elliptic_curve_public_key table
    let identity_key_id = insert_elliptic_curve_public_key(&key_bundle.identity_key.0, connection)?;
    let identity_key_timestamp = datetime_to_timestamp(&key_bundle.identity_key.1);

    // Insert the signed curve prekey into the signed_curve_prekey table
    let signed_curve_prekey_id =
        insert_signed_curve_prekey(&key_bundle.signed_curve_prekey.0, connection)?;
    let signed_curve_prekey_timestamp = datetime_to_timestamp(&key_bundle.signed_curve_prekey.1);

    // Insert the signed last resort PQKEM prekey into the signed_pqkem_prekey table
    let signed_last_resort_pqkem_prekey_id =
        insert_signed_pqkem_prekey(&key_bundle.signed_last_resort_pqkem_prekey.0, connection)?;
    let signed_last_resort_pqkem_prekey_timestamp =
        datetime_to_timestamp(&key_bundle.signed_last_resort_pqkem_prekey.1);

    // Insert the key bundle into the key_bundle table
    let key_bundle_id = insert_returning_id(
        REQ_INSERT_KEY_BUNDLE,
        params![
            identity_key_id,
            identity_key_timestamp,
            signed_curve_prekey_id,
            signed_curve_prekey_timestamp,
            signed_last_resort_pqkem_prekey_id,
            signed_last_resort_pqkem_prekey_timestamp,
        ],
        "key_bundle",
        connection,
    )?;

    // Insert the one-time curve prekeys
    insert_one_time_curve_prekey_set(
        &key_bundle.one_time_curve_prekeys,
        key_bundle_id,
        &connection,
    )?;

    // Insert the signed one-time PQKEM prekeys
    insert_signed_one_time_pqkem_prekey_set(
        &key_bundle.signed_one_time_pqkem_prekeys,
        key_bundle_id,
        &connection,
    )?;

    Ok(key_bundle_id)
}

// Updates the signed_curve_prekey_id and signed_curve_prekey_timestamp fields of a key_bundle entry to the given parameters.
// The new key has to be inserted beforehand
pub fn update_key_bundle_signed_curve_prekey(
    key_bundle_id: i32,
    new_key_id: i32,
    timestamp: &DateTime<Utc>,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Perform the update
    let rows_modified = perform_update(
        REQ_UPDATE_KEY_BUNDLE_SIGNED_CURVE_PREKEY,
        params![key_bundle_id, new_key_id, datetime_to_timestamp(timestamp),],
        connection,
    )?;

    // Check that exactly one row was modified
    if rows_modified != 1 {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::KeyBundleNotFound,
        ));
    }

    Ok(())
}

// Updates the signed_last_resort_pqkem_prekey_id and signed_last_resort_pqkem_prekey_timestamp fields of a key_bundle entry to the given parameters.
// The new key has to be inserted beforehand
pub fn update_key_bundle_signed_last_resort_pqkem_prekey(
    key_bundle_id: i32,
    new_key_id: i32,
    timestamp: &DateTime<Utc>,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Perform the update
    let rows_modified = perform_update(
        REQ_UPDATE_KEY_BUNDLE_SIGNED_LAST_RESORT_PQKEM_PREKEY,
        params![key_bundle_id, new_key_id, datetime_to_timestamp(timestamp),],
        connection,
    )?;

    // Check that exactly one row was modified
    if rows_modified != 1 {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::KeyBundleNotFound,
        ));
    }

    Ok(())
}
