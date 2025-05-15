use e2ee_rust_common::{
    crypto::curve::keys::{EllipticCurveKeyPair, IdentifiedEllipticCurveKeyPair},
    storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::{
    utils::{insert_returning_id, uuid_from_bytes},
    ToStorageInterfaceError,
};

use super::{
    consts::{REQ_GET_CLIENT_ONE_TIME_CURVE_PREKEY, REQ_INSERT_ONE_TIME_CURVE_PREKEY},
    identified_elliptic_curve_keypair::insert_identified_elliptic_curve_keypair,
};

pub fn insert_one_time_curve_prekey(
    client_db_id: i32,
    identified_elliptic_curve_keypair_id: i32,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    Ok(insert_returning_id(
        REQ_INSERT_ONE_TIME_CURVE_PREKEY,
        params![client_db_id, identified_elliptic_curve_keypair_id],
        "one_time_curve_prekey",
        connection,
    )?)
}

pub fn insert_one_time_curve_prekey_set(
    client_db_id: i32,
    one_time_curve_prekeys: &[IdentifiedEllipticCurveKeyPair],
    connection: &Connection,
) -> Result<(), StorageInterfaceError> {
    // Loop through the one-time curve prekeys
    for prekey in one_time_curve_prekeys {
        // Insert the one-time curve prekey
        let prekey_id = insert_identified_elliptic_curve_keypair(prekey, connection)?;

        // Insert the one-time curve prekey
        insert_one_time_curve_prekey(client_db_id, prekey_id, connection)?;
    }
    Ok(())
}

pub fn get_client_one_time_curve_prekey_set(
    client_db_id: i32,
    connection: &Connection,
) -> Result<Vec<IdentifiedEllipticCurveKeyPair>, StorageInterfaceError> {
    // Prepare the statement
    let mut stmt = connection
        .prepare_cached(REQ_GET_CLIENT_ONE_TIME_CURVE_PREKEY)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = stmt
        .query(params![client_db_id])
        .to_storage_interface_error()?;

    // Loop through the rows
    let mut one_time_curve_prekeys = Vec::new();
    while let Some(row) = rows.next().to_storage_interface_error()? {
        // Get the values
        let identified_elliptic_curve_key_uuid: Vec<u8> =
            row.get(0).to_storage_interface_error()?;
        let elliptic_curve_keytype: i32 = row.get(1).to_storage_interface_error()?;
        let elliptic_curve_public_key: Vec<u8> = row.get(2).to_storage_interface_error()?;
        let elliptic_curve_private_key: Vec<u8> = row.get(3).to_storage_interface_error()?;

        // Create the identified elliptic curve keypair
        let identified_elliptic_curve_keypair = IdentifiedEllipticCurveKeyPair {
            id: uuid_from_bytes(&identified_elliptic_curve_key_uuid)?,
            key_pair: EllipticCurveKeyPair::from_bytes(
                elliptic_curve_keytype as u8,
                elliptic_curve_public_key,
                elliptic_curve_private_key,
            )?,
        };

        // Add the one time curve prekey to the vector
        one_time_curve_prekeys.push(identified_elliptic_curve_keypair);
    }

    // Return the one time curve prekeys
    Ok(one_time_curve_prekeys)
}
