use e2ee_rust_common::{
    crypto::{curve::keys::IdentifiedEllipticCurveKeyPair, pqkem::keys::IdentifiedPQKEMKeyPair},
    pqxdh::private_bundle::PrivateBundle,
    storage::{
        client::{errors::ClientStorageError, traits::ClientStorage},
        errors::StorageInterfaceError,
    },
};
use uuid::Uuid;

use crate::{SQLiteStorage, ToStorageInterfaceError, CLIENT_SCHEMA_VERSION};

use super::{
    client::{
        get_client_key_bundle, get_client_uuid, insert_client, update_client_curve_prekey,
        update_client_last_resort_pqkem_prekey,
    },
    elliptic_curve_keypair::insert_elliptic_curve_keypair,
    identified_elliptic_curve_keypair::insert_identified_elliptic_curve_keypair,
    identified_pqkem_keypair::insert_identified_pqkem_keypair,
    one_time_curve_prekey::insert_one_time_curve_prekey_set,
    one_time_pqkem_prekey::insert_one_time_pqkem_prekey_set,
};

impl ClientStorage for SQLiteStorage {
    fn init_client(&self) -> Result<(), StorageInterfaceError> {
        self.init(include_str!("schema_client.sql"), CLIENT_SCHEMA_VERSION)
    }

    fn contains_client(&self) -> Result<Option<i32>, StorageInterfaceError> {
        // We check if a client exists in the client table
        let mut statement = self
            .connection
            .prepare_cached("SELECT id FROM client")
            .to_storage_interface_error()?;
        let query = statement.query_row([], |row| row.get(0));

        // If the query returns no rows, we return None
        if query.is_err() {
            let err = query.as_ref().err().unwrap();
            if err == &rusqlite::Error::QueryReturnedNoRows {
                return Ok(None);
            }
            return Err(query.to_storage_interface_error().err().unwrap());
        } else {
            // If the query returns a row, we return the id
            let count: i32 = query.unwrap();
            Ok(Some(count))
        }
    }

    fn create_client(
        &self,
        client_id: &uuid::Uuid,
        private_key_bundle: &PrivateBundle,
    ) -> Result<(), StorageInterfaceError> {
        // Insert the identity key
        let identity_key_id =
            insert_elliptic_curve_keypair(&private_key_bundle.identity_key, &self.connection)?;

        // Insert the curve prekey
        let curve_prekey_id = insert_identified_elliptic_curve_keypair(
            &private_key_bundle.curve_prekey,
            &self.connection,
        )?;

        // Insert the last resort prekey
        let last_resort_prekey_id = insert_identified_pqkem_keypair(
            &private_key_bundle.last_resort_prekey,
            &self.connection,
        )?;

        // Insert the client
        let client_db_id = insert_client(
            client_id,
            identity_key_id,
            curve_prekey_id,
            last_resort_prekey_id,
            &self.connection,
        )?;

        // Insert the one-time curve prekeys
        insert_one_time_curve_prekey_set(
            client_db_id,
            &private_key_bundle.one_time_curve_prekeys,
            &self.connection,
        )?;

        // Insert the one-time pqkem prekeys
        insert_one_time_pqkem_prekey_set(
            client_db_id,
            &private_key_bundle.one_time_pqkem_prekeys,
            &self.connection,
        )?;

        Ok(())
    }

    fn get_client_uuid(&self) -> Result<Uuid, StorageInterfaceError> {
        get_client_uuid(&self.connection)
    }

    fn get_private_key_bundle(&self) -> Result<PrivateBundle, StorageInterfaceError> {
        get_client_key_bundle(&self.connection)
    }

    fn update_curve_signed_prekey(
        &self,
        new_signed_prekey: &IdentifiedEllipticCurveKeyPair,
    ) -> Result<(), StorageInterfaceError> {
        // Get the client database id
        let client_db_id =
            self.contains_client()?
                .ok_or(StorageInterfaceError::ClientStorageError(
                    ClientStorageError::ClientNotFound,
                ))?;

        // Add the new identified elliptic curve keypair
        let new_signed_prekey_id =
            insert_identified_elliptic_curve_keypair(new_signed_prekey, &self.connection)?;

        // Update the client curve prekey
        update_client_curve_prekey(client_db_id, new_signed_prekey_id, &self.connection)?;

        Ok(())
    }

    fn update_last_resort_pqkem_prekey(
        &self,
        new_last_resort_prekey: &IdentifiedPQKEMKeyPair,
    ) -> Result<(), StorageInterfaceError> {
        // Get the client database id
        let client_db_id =
            self.contains_client()?
                .ok_or(StorageInterfaceError::ClientStorageError(
                    ClientStorageError::ClientNotFound,
                ))?;

        // Add the new identified PQKEM keypair
        let new_last_resort_prekey_id =
            insert_identified_pqkem_keypair(new_last_resort_prekey, &self.connection)?;

        // Update the client last resort PQKEM prekey
        update_client_last_resort_pqkem_prekey(
            client_db_id,
            new_last_resort_prekey_id,
            &self.connection,
        )?;

        Ok(())
    }

    fn add_curve_one_time_prekeys(
        &self,
        new_one_time_prekeys: &Vec<IdentifiedEllipticCurveKeyPair>,
    ) -> Result<(), StorageInterfaceError> {
        // Get the client database id
        let client_db_id =
            self.contains_client()?
                .ok_or(StorageInterfaceError::ClientStorageError(
                    ClientStorageError::ClientNotFound,
                ))?;

        // Add the new identified elliptic curve keypairs
        insert_one_time_curve_prekey_set(client_db_id, new_one_time_prekeys, &self.connection)?;

        Ok(())
    }

    fn add_signed_pqkem_prekeys(
        &self,
        new_signed_pqkem_prekeys: &Vec<IdentifiedPQKEMKeyPair>,
    ) -> Result<(), StorageInterfaceError> {
        // Get the client database id
        let client_db_id =
            self.contains_client()?
                .ok_or(StorageInterfaceError::ClientStorageError(
                    ClientStorageError::ClientNotFound,
                ))?;
        // Add the new identified PQKEM keypairs
        insert_one_time_pqkem_prekey_set(client_db_id, new_signed_pqkem_prekeys, &self.connection)?;
        Ok(())
    }
}
