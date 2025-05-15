use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    pqxdh::{
        one_time_curve_prekey_set::OneTimeCurvePrekeySet, signed_curve_prekey::SignedCurvePrekey,
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    storage::errors::StorageInterfaceError,
};

use super::client_structs::ClientInformation;

pub trait ServerStorage {
    // Initializes the server storage
    fn init_server(&self) -> Result<(), StorageInterfaceError>;

    // Fetches the client information from the storage
    // Returns a ClientNotFound error if the client is not found
    // Returns a CustomError if there is an error fetching the client
    fn get_client(&self, client_id: &Uuid) -> Result<ClientInformation, StorageInterfaceError>;

    // Adds a client to the storage
    // Returns a ClientAlreadyExists error if the client is already registered
    fn add_client(
        &mut self,
        client_id: Uuid,
        client: &ClientInformation,
    ) -> Result<(), StorageInterfaceError>;

    // Updates a client's signed curve prekey
    fn update_signed_curve_prekey(
        &mut self,
        client_id: Uuid,
        new_key: &SignedCurvePrekey,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), StorageInterfaceError>;

    // Updates a client's signed last resort PQKEM prekey
    fn update_signed_last_resort_pqkem_prekey(
        &mut self,
        client_id: Uuid,
        new_key: &SignedPQKEMPrekey,
        timestamp: &DateTime<Utc>,
    ) -> Result<(), StorageInterfaceError>;

    // Adds new one time curve prekeys to a client's key bundle
    fn add_one_time_curve_prekeys(
        &mut self,
        client_id: Uuid,
        new_keys: &OneTimeCurvePrekeySet,
    ) -> Result<(), StorageInterfaceError>;

    // Adds new signed one time PQKEM prekeys to a client's key bundle
    fn add_signed_one_time_pqkem_prekeys(
        &mut self,
        client_id: Uuid,
        new_key: &SignedOneTimePqkemPrekeySet,
    ) -> Result<(), StorageInterfaceError>;
}
