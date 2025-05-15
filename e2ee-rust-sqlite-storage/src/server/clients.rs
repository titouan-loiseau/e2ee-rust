use e2ee_rust_common::storage::{
    errors::StorageInterfaceError, server::client_structs::ClientKeyBundle,
};
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::utils::insert_returning_id;

use super::{consts::REQ_INSERT_CLIENT, key_bundle::insert_key_bundle};

pub fn insert_client(
    client_uuid: Uuid,
    key_bundle: &ClientKeyBundle,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the key bundle into the database and get the ID
    let key_bundle_id = insert_key_bundle(key_bundle, connection)?;

    // Insert the client and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_CLIENT,
        params![client_uuid.as_bytes(), key_bundle_id],
        "client",
        connection,
    )?)
}
