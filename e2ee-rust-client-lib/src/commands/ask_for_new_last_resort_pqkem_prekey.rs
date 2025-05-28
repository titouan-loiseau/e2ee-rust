use e2ee_rust_common::{
    crypto::{
        curve::traits::EllipticCurveAlgorithm,
        pqkem::{keys::IdentifiedPQKEMPublicKey, traits::PQKEMAlgorithm},
    },
    errors::general::{GeneralError, ToGeneralError},
    messages::client::{
        client_message::{ClientMessage, ClientMessageType},
        new_keys::{NewKeys, NewKeysType},
    },
    pqxdh::signed_pqkem_prekey::SignedPQKEMPrekey,
    storage::client::traits::ClientStorage,
};
use log::{debug, error};
use rand::{CryptoRng, RngCore};

use crate::ClientData;

pub fn command_ask_for_new_last_resort_pqkem_prekey<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
    R: RngCore + CryptoRng,
>(
    client: &ClientData<T, U, S>,
    rng: &mut R,
) -> Result<ClientMessage, GeneralError> {
    // Generate a new signed pqkem prekey and the signature
    let new_last_resort_prekey = client.pqkem_algorithm.generate_identified_key_pair(rng);

    // Sign the new last resort prekey
    let signature = {
        // Lock the client storage
        let client_storage = client.client_storage_mutex.lock().unwrap();

        // Sign the new last resort prekey
        let signature = client
            .curve_algorithm
            .xeddsa_sign(
                &client_storage
                    .get_private_key_bundle()
                    .to_general_error()?
                    .identity_key
                    .private_key,
                &new_last_resort_prekey.key_pair.public_key.encode_kem(),
                rng,
            )
            .map_err(|e| GeneralError::XedDSA(e))?;

        // Store it in the private bundle
        client_storage
            .update_last_resort_pqkem_prekey(&new_last_resort_prekey)
            .map_err(|e| {
                error!("Failed to update last resort pqkem prekey: {:?}", e);
                GeneralError::StorageError(e)
            })?;
        debug!("Updated last resort pqkem prekey");
        signature
    };

    // Return the message
    let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client.client_uuid);
    msg.new_keys = Some(NewKeys {
        keys_type: NewKeysType::SignedLastResortPQKEMPrekey,
        signed_curve_prekey: None,
        signed_last_resort_pqkem_prekey: Some(SignedPQKEMPrekey {
            identified_public_key: IdentifiedPQKEMPublicKey::from_identified_key_pair(
                &new_last_resort_prekey,
            ),
            signature,
        }),
        one_time_curve_prekey_set: None,
        signed_one_time_pqkem_prekey_set: None,
    });

    Ok(msg)
}
