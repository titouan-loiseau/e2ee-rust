use e2ee_rust_common::{
    crypto::curve::keys::IdentifiedEllipticCurvePublicKey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{
    utils::{insert_returning_id, uuid_from_bytes},
    ToStorageInterfaceError,
};

use super::{
    consts::{
        REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY,
        REQ_QUERY_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY,
    },
    elliptic_curve_public_key::{get_elliptic_curve_public_key, insert_elliptic_curve_public_key},
};

pub fn get_identified_elliptic_curve_public_key(
    db_key_id: i32,
    connection: &Connection,
) -> Result<IdentifiedEllipticCurvePublicKey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut identity_key_rows = statement.query([db_key_id]).to_storage_interface_error()?;

    // Get the row
    if let Some(identity_key_row) = identity_key_rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(
            ServerStorageError::IdentifiedEllipticCurvePublicKeyNotFound,
        )
    })? {
        // Get the fields
        let uuid: Vec<u8> = identity_key_row.get(0).to_storage_interface_error()?;
        let elliptic_curve_public_key_id: i32 =
            identity_key_row.get(1).to_storage_interface_error()?;

        // Get the elliptic curve public key
        let elliptic_curve_public_key =
            get_elliptic_curve_public_key(elliptic_curve_public_key_id, connection)?;

        Ok(IdentifiedEllipticCurvePublicKey {
            id: uuid_from_bytes(&uuid)?,
            public_key: elliptic_curve_public_key,
        })
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::IdentifiedEllipticCurvePublicKeyNotFound,
        ));
    }
}

pub fn insert_identified_elliptic_curve_public_key(
    key: &IdentifiedEllipticCurvePublicKey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the elliptic curve public key
    let elliptic_curve_public_key_id =
        insert_elliptic_curve_public_key(&key.public_key, connection)?;

    // Insert the identified elliptic curve public key and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_PUBLIC_KEY,
        params![key.id.as_bytes(), elliptic_curve_public_key_id],
        "identified_elliptic_curve_public_key",
        connection,
    )?)
}
