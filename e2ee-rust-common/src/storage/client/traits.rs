use uuid::Uuid;

use crate::{
    crypto::{curve::keys::IdentifiedEllipticCurveKeyPair, pqkem::keys::IdentifiedPQKEMKeyPair},
    pqxdh::private_bundle::PrivateBundle,
    storage::errors::StorageInterfaceError,
};

pub trait ClientStorage {
    // Initializes the client storage
    fn init_client(&self) -> Result<(), StorageInterfaceError>;

    // Checks if the storage contains the client's informations and private key bundle, and returns the client database ID if it does
    fn contains_client(&self) -> Result<Option<i32>, StorageInterfaceError>;

    // Creates a client from the given client id and private key bundle
    fn create_client(
        &self,
        client_id: &Uuid,
        private_key_bundle: &PrivateBundle,
    ) -> Result<(), StorageInterfaceError>;

    // Gets the client UUID
    fn get_client_uuid(&self) -> Result<Uuid, StorageInterfaceError>;

    // Fetches the client's private key bundle
    fn get_private_key_bundle(&self) -> Result<PrivateBundle, StorageInterfaceError>;

    // Updates the curve signed prekey
    fn update_curve_signed_prekey(
        &self,
        new_signed_prekey: &IdentifiedEllipticCurveKeyPair,
    ) -> Result<(), StorageInterfaceError>;

    // Updates the last resort pqkem prekey
    fn update_last_resort_pqkem_prekey(
        &self,
        new_last_resort_prekey: &IdentifiedPQKEMKeyPair,
    ) -> Result<(), StorageInterfaceError>;

    // Adds new curve one time prekeys
    fn add_curve_one_time_prekeys(
        &self,
        new_one_time_prekeys: &Vec<IdentifiedEllipticCurveKeyPair>,
    ) -> Result<(), StorageInterfaceError>;

    // Adds new signed PQKEM prekeys
    fn add_signed_pqkem_prekeys(
        &self,
        new_signed_pqkem_prekeys: &Vec<IdentifiedPQKEMKeyPair>,
    ) -> Result<(), StorageInterfaceError>;
}
