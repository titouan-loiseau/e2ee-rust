use e2ee_rust_common::{
    pqxdh::signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
    storage::errors::StorageInterfaceError,
};
use rusqlite::{params, Connection};

use crate::{utils::insert_returning_id, ToStorageInterfaceError};

use super::{
    consts::{REQ_INSERT_SIGNED_ONE_TIME_PQKEM_PREKEY, REQ_QUERY_SIGNED_ONE_TIME_PQKEM_PREKEY_SET},
    signed_pqkem_prekey::{get_signed_pqkem_prekey, insert_signed_pqkem_prekey},
};

pub fn get_signed_one_time_pqkem_prekey_set(
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<SignedOneTimePqkemPrekeySet, StorageInterfaceError> {
    // Result
    let mut res: SignedOneTimePqkemPrekeySet = SignedOneTimePqkemPrekeySet { prekeys: vec![] };

    // Create the statement
    let mut statement = connection
        .prepare_cached(REQ_QUERY_SIGNED_ONE_TIME_PQKEM_PREKEY_SET)
        .to_storage_interface_error()?;

    // Execute the statement
    let mut rows = statement
        .query([key_bundle_id])
        .to_storage_interface_error()?;

    // Loop through the rows
    while let Some(row) = rows.next().to_storage_interface_error()? {
        // Get the prekey id
        let prekey_id: i32 = row.get(0).to_storage_interface_error()?;

        // Get the signed pqkem prekey
        let prekey = get_signed_pqkem_prekey(prekey_id, connection)?;

        // Add the prekey to the result
        res.prekeys.push(prekey);
    }

    Ok(res)
}

pub fn insert_signed_one_time_pqkem_prekey_set(
    signed_one_time_pqkem_prekey_set: &SignedOneTimePqkemPrekeySet,
    key_bundle_id: i32,
    connection: &Connection,
) -> Result<Vec<i32>, StorageInterfaceError> {
    let mut res = Vec::new();

    // Loop through all the prekeys
    for prekey in signed_one_time_pqkem_prekey_set.prekeys.iter() {
        // Insert the prekey
        let prekey_id = insert_signed_pqkem_prekey(prekey, connection)?;

        // Insert the signed one time PQKEM prekey and return the new ID
        let id = insert_returning_id(
            REQ_INSERT_SIGNED_ONE_TIME_PQKEM_PREKEY,
            params![prekey_id, key_bundle_id],
            "signed_one_time_pqkem_prekey",
            connection,
        )?;

        // Add the id to the result
        res.push(id);
    }

    Ok(res)
}
