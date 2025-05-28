use chrono::{DateTime, Utc};
use e2ee_rust_common::{
    pqxdh::{
        one_time_curve_prekey_set::OneTimeCurvePrekeySet, signed_curve_prekey::SignedCurvePrekey,
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    storage::{
        errors::StorageInterfaceError,
        server::{client_structs::ClientInformation, traits::ServerStorage},
    },
};
use uuid::Uuid;

use crate::{SQLiteStorage, SERVER_SCHEMA_VERSION};

use super::{
    clients::insert_client,
    key_bundle::{
        get_client_key_bundle_id, get_key_bundle_from_id, update_key_bundle_signed_curve_prekey,
        update_key_bundle_signed_last_resort_pqkem_prekey,
    },
    one_time_curve_prekey::insert_one_time_curve_prekey_set,
    signed_curve_prekey::insert_signed_curve_prekey,
    signed_one_time_pqkem_prekey::insert_signed_one_time_pqkem_prekey_set,
    signed_pqkem_prekey::insert_signed_pqkem_prekey,
};

impl ServerStorage for SQLiteStorage {
    fn init_server(&self) -> Result<(), StorageInterfaceError> {
        self.init(include_str!("schema_server.sql"), SERVER_SCHEMA_VERSION)
    }

    fn get_client(&self, client_id: &Uuid) -> Result<ClientInformation, StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        // Get the key bundle id from the clients table
        let key_bundle_id = get_client_key_bundle_id(*client_id, &conn)?;

        // Get the key bundle from the key_bundle table
        let key_bundle = get_key_bundle_from_id(key_bundle_id, &conn)?;

        Ok(ClientInformation { key_bundle })
    }

    fn add_client(
        &mut self,
        client_id: Uuid,
        client: &ClientInformation,
    ) -> Result<(), StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        insert_client(client_id, &client.key_bundle, &conn)?;
        Ok(())
    }

    fn update_signed_curve_prekey(
        &mut self,
        client_id: Uuid,
        new_key: &SignedCurvePrekey,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        // Get the client's key bundle ID
        let key_bundle_id = get_client_key_bundle_id(client_id, &conn)?;

        // Add the new prekey in the database
        let new_signed_curve_prekey_id = insert_signed_curve_prekey(new_key, &conn)?;

        // Update the key bundle to use the new key
        update_key_bundle_signed_curve_prekey(
            key_bundle_id,
            new_signed_curve_prekey_id,
            timestamp,
            &conn,
        )?;

        // TODO: Delete the old key

        Ok(())
    }

    fn update_signed_last_resort_pqkem_prekey(
        &mut self,
        client_id: Uuid,
        new_key: &SignedPQKEMPrekey,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        // Get the client's key bundle ID
        let key_bundle_id = get_client_key_bundle_id(client_id, &conn)?;

        // Add the new prekey in the database
        let new_signed_last_resort_pqkem_prekey_id = insert_signed_pqkem_prekey(new_key, &conn)?;

        // Update the key bundle to use the new key
        update_key_bundle_signed_last_resort_pqkem_prekey(
            key_bundle_id,
            new_signed_last_resort_pqkem_prekey_id,
            timestamp,
            &conn,
        )?;

        // TODO: Delete the old key

        Ok(())
    }

    fn add_one_time_curve_prekeys(
        &mut self,
        client_id: Uuid,
        new_keys: &OneTimeCurvePrekeySet,
    ) -> Result<(), StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        // Get the client's key bundle ID
        let key_bundle_id = get_client_key_bundle_id(client_id, &conn)?;

        // Add the new prekeys in the database
        insert_one_time_curve_prekey_set(new_keys, key_bundle_id, &conn)?;

        Ok(())
    }

    fn add_signed_one_time_pqkem_prekeys(
        &mut self,
        client_id: Uuid,
        new_keys: &SignedOneTimePqkemPrekeySet,
    ) -> Result<(), StorageInterfaceError> {
        // Get the connection
        let conn = self.pool.get().unwrap();

        // Get the client's key bundle ID
        let key_bundle_id = get_client_key_bundle_id(client_id, &conn)?;

        // Add the new prekeys in the database
        insert_signed_one_time_pqkem_prekey_set(new_keys, key_bundle_id, &conn)?;

        Ok(())
    }
}
