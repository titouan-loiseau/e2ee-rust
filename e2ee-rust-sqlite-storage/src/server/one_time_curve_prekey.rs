use e2ee_rust_common::{
    pqxdh::one_time_curve_prekey_set::OneTimeCurvePrekeySet, storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::{utils::insert_returning_id, ToStorageInterfaceError};

use super::{
    consts::{REQ_INSERT_ONE_TIME_CURVE_PREKEY, REQ_QUERY_ONE_TIME_CURVE_PREKEY_SET},
    identified_elliptic_curve_public_key::{
        get_identified_elliptic_curve_public_key, insert_identified_elliptic_curve_public_key,
    },
};

pub fn get_one_time_curve_prekey_set(
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<OneTimeCurvePrekeySet, StorageInterfaceError> {
    // Result
    let mut res: OneTimeCurvePrekeySet = OneTimeCurvePrekeySet { prekeys: vec![] };

    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_ONE_TIME_CURVE_PREKEY_SET)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement
        .query([key_bundle_id])
        .to_storage_interface_error()?;

    // Loop through the rows
    while let Some(row) = rows.next().to_storage_interface_error()? {
        // Get the prekey id
        let prekey_id: i32 = row.get(0).to_storage_interface_error()?;

        // Get the identified elliptic curve public key
        let prekey = get_identified_elliptic_curve_public_key(prekey_id, connection)?;

        // Add the prekey to the result
        res.prekeys.push(prekey);
    }

    Ok(res)
}

pub fn insert_one_time_curve_prekey_set(
    one_time_curve_prekey_set: &OneTimeCurvePrekeySet,
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<Vec<i32>, StorageInterfaceError> {
    let mut res = Vec::new();

    // Loop through all the prekeys
    for prekey in one_time_curve_prekey_set.prekeys.iter() {
        // Insert the prekey
        let prekey_id = insert_identified_elliptic_curve_public_key(prekey, connection)?;

        // Insert the identified PQKEM public key and return the new ID
        let id = insert_returning_id(
            REQ_INSERT_ONE_TIME_CURVE_PREKEY,
            params![prekey_id, key_bundle_id],
            "one_time_curve_prekey",
            connection,
        )?;

        // Add the id to the result
        res.push(id);
    }

    Ok(res)
}
