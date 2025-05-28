use e2ee_rust_common::{
    crypto::{
        curve::{
            keys::{IdentifiedEllipticCurveKeyPair, IdentifiedEllipticCurvePublicKey},
            traits::EllipticCurveAlgorithm,
        },
        pqkem::traits::PQKEMAlgorithm,
    },
    errors::general::GeneralError,
    messages::client::{
        client_message::{ClientMessage, ClientMessageType},
        new_keys::{NewKeys, NewKeysType},
    },
    pqxdh::one_time_curve_prekey_set::OneTimeCurvePrekeySet,
    storage::client::traits::ClientStorage,
};
use log::{debug, error};
use rand::{CryptoRng, RngCore};

use crate::{ClientData, ONE_TIME_CURVE_PREKEYS};

pub fn command_ask_for_new_curve_onetime_prekeys<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
    R: RngCore + CryptoRng,
>(
    client: &ClientData<T, U, S>,
    rng: &mut R,
) -> Result<ClientMessage, GeneralError> {
    // Generate a new set of curve one time prekeys
    let new_keys: Vec<IdentifiedEllipticCurveKeyPair> = (0..ONE_TIME_CURVE_PREKEYS)
        .into_iter()
        .map(|_| client.curve_algorithm.generate_identified_key_pair(rng))
        .collect();

    // Store it in the private bundle
    {
        // Lock the client storage
        let client_storage = client.client_storage_mutex.lock().unwrap();

        // Add the new keys to the storage
        client_storage
            .add_curve_one_time_prekeys(&new_keys)
            .map_err(|e| {
                error!("Failed to add curve one time prekeys: {:?}", e);
                GeneralError::StorageError(e)
            })?;
        debug!("Added {} new one time curve prekeys", new_keys.len());
    }

    // Return the message
    let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client.client_uuid);
    msg.new_keys = Some(NewKeys {
        keys_type: NewKeysType::OneTimeCurvePrekeySet,
        signed_curve_prekey: None,
        signed_last_resort_pqkem_prekey: None,
        one_time_curve_prekey_set: Some(OneTimeCurvePrekeySet {
            prekeys: new_keys
                .iter()
                .map(|k| IdentifiedEllipticCurvePublicKey::from_identified_key_pair(k))
                .collect(),
        }),
        signed_one_time_pqkem_prekey_set: None,
    });

    Ok(msg)
}
