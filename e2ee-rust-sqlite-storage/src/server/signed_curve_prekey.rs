use e2ee_rust_common::{
    pqxdh::signed_curve_prekey::SignedCurvePrekey,
    storage::{errors::StorageInterfaceError, server::errors::ServerStorageError},
};
use rusqlite::{params, Connection};

use crate::{
    server::consts::REQ_DELETE_SIGNED_CURVE_PREKEY,
    utils::{insert_returning_id, perform_delete},
    ToStorageInterfaceError,
};

use super::{
    consts::{REQ_INSERT_SIGNED_CURVE_PREKEY, REQ_QUERY_SIGNED_CURVE_PREKEY},
    identified_elliptic_curve_public_key::{
        get_identified_elliptic_curve_public_key, insert_identified_elliptic_curve_public_key,
    },
};

pub fn get_signed_curve_prekey(
    id: i32,
    connection: &Connection,
) -> Result<SignedCurvePrekey, StorageInterfaceError> {
    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_SIGNED_CURVE_PREKEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut signed_curve_prekey_rows = statement.query([id]).to_storage_interface_error()?;

    // Get the row
    if let Some(signed_curve_prekey_row) = signed_curve_prekey_rows.next().map_err(|_| {
        StorageInterfaceError::ServerStorageError(ServerStorageError::SignedCurvePrekeyNotFound)
    })? {
        // Get the fields from the row
        let identified_public_key_id: i32 = signed_curve_prekey_row
            .get(0)
            .to_storage_interface_error()?;
        let signature: Vec<u8> = signed_curve_prekey_row
            .get(1)
            .to_storage_interface_error()?;

        // Get the identified elliptic curve public key
        let identified_public_key =
            get_identified_elliptic_curve_public_key(identified_public_key_id, connection)?;

        Ok(SignedCurvePrekey {
            identified_public_key,
            signature: signature
                .try_into()
                .map_err(|_| StorageInterfaceError::BadSignature)?,
        })
    } else {
        return Err(StorageInterfaceError::ServerStorageError(
            ServerStorageError::SignedCurvePrekeyNotFound,
        ));
    }
}

pub fn insert_signed_curve_prekey(
    key: &SignedCurvePrekey,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Insert the identified elliptic curve public key
    let identified_pqkem_public_key_id =
        insert_identified_elliptic_curve_public_key(&key.identified_public_key, connection)?;

    // Insert the signed curve prekey and return the new ID
    Ok(insert_returning_id(
        REQ_INSERT_SIGNED_CURVE_PREKEY,
        params![identified_pqkem_public_key_id, &key.signature],
        "signed_curve_prekey",
        connection,
    )?)
}

pub fn delete_signed_curve_prekey(
    db_key_id: i32,
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    perform_delete(
        REQ_DELETE_SIGNED_CURVE_PREKEY,
        params![db_key_id],
        connection,
    )
}
