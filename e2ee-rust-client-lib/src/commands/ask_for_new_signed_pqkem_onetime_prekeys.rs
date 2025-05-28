use e2ee_rust_common::{
    crypto::{
        curve::traits::EllipticCurveAlgorithm,
        pqkem::{
            keys::{IdentifiedPQKEMKeyPair, IdentifiedPQKEMPublicKey},
            traits::PQKEMAlgorithm,
        },
    },
    errors::general::{GeneralError, ToGeneralError},
    messages::client::{
        client_message::{ClientMessage, ClientMessageType},
        new_keys::{NewKeys, NewKeysType},
    },
    pqxdh::{
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    storage::client::traits::ClientStorage,
};
use log::{debug, error};
use rand::{CryptoRng, RngCore};

use crate::{ClientData, ONE_TIME_PQKEM_PREKEYS};

pub fn command_ask_for_new_signed_pqkem_onetime_prekeys<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
    R: RngCore + CryptoRng,
>(
    client: &ClientData<T, U, S>,
    rng: &mut R,
) -> Result<ClientMessage, GeneralError> {
    // Generate a new set of pqkem one time prekeys
    let new_keys: Vec<IdentifiedPQKEMKeyPair> = (0..ONE_TIME_PQKEM_PREKEYS)
        .into_iter()
        .map(|_| client.pqkem_algorithm.generate_identified_key_pair(rng))
        .collect();

    // Generate the signatures
    let signatures: Vec<[u8; 64]> = {
        // Lock the client storage
        let client_storage = client.client_storage_mutex.lock().unwrap();

        // Sign the new keys
        let signatures = new_keys
            .clone()
            .into_iter()
            .map(|k| {
                client
                    .curve_algorithm
                    .xeddsa_sign(
                        &client_storage
                            .get_private_key_bundle()
                            .to_general_error()?
                            .identity_key
                            .private_key,
                        &k.key_pair.public_key.encode_kem(),
                        rng,
                    )
                    .map_err(|e| GeneralError::XedDSA(e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Append them to the current one time prekeys
        client_storage
            .add_signed_pqkem_prekeys(&new_keys)
            .map_err(|e| {
                error!("Failed to add signed one time PQKEM prekeys: {:?}", e);
                GeneralError::StorageError(e)
            })?;
        debug!("Added {} new signed one time PQKEM prekeys", new_keys.len());
        signatures
    };

    // Return the message
    let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client.client_uuid);
    msg.new_keys = Some(NewKeys {
        keys_type: NewKeysType::SignedOneTimePQKEMPrekeySet,
        signed_curve_prekey: None,
        signed_last_resort_pqkem_prekey: None,
        one_time_curve_prekey_set: None,
        signed_one_time_pqkem_prekey_set: Some(SignedOneTimePqkemPrekeySet {
            prekeys: new_keys
                .iter()
                .enumerate()
                .map(|(i, k)| SignedPQKEMPrekey {
                    identified_public_key: IdentifiedPQKEMPublicKey::from_identified_key_pair(k),
                    signature: signatures[i],
                })
                .collect(),
        }),
    });

    Ok(msg)
}
