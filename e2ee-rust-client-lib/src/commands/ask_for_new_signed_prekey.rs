use e2ee_rust_common::{
    crypto::{
        curve::{
            keys::{IdentifiedEllipticCurveKeyPair, IdentifiedEllipticCurvePublicKey},
            traits::EllipticCurveAlgorithm,
        },
        pqkem::traits::PQKEMAlgorithm,
    },
    errors::general::{GeneralError, ToGeneralError},
    messages::client::{
        client_message::{ClientMessage, ClientMessageType},
        new_keys::{NewKeys, NewKeysType},
    },
    pqxdh::signed_curve_prekey::SignedCurvePrekey,
    storage::client::traits::ClientStorage,
};
use log::{debug, error};
use rand::{CryptoRng, RngCore};

use crate::ClientData;

pub fn command_ask_for_new_signed_prekey<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
    R: RngCore + CryptoRng,
>(
    client: &ClientData<T, U, S>,
    rng: &mut R,
) -> Result<ClientMessage, GeneralError> {
    // Generate a new curve signed prekey and the signature
    let new_signed_prekey: IdentifiedEllipticCurveKeyPair =
        client.curve_algorithm.generate_identified_key_pair(rng);

    // Create the signature for the new signed prekey

    let signature = {
        // Lock the client storage
        let client_storage = client.client_storage_mutex.lock().unwrap();

        // Generate the signature
        let signature = client
            .curve_algorithm
            .xeddsa_sign(
                &client_storage
                    .get_private_key_bundle()
                    .to_general_error()?
                    .identity_key
                    .private_key,
                &new_signed_prekey.key_pair.public_key.encode_ec(),
                rng,
            )
            .map_err(|e| GeneralError::XedDSA(e))?;

        // Store it in the private bundle
        client_storage
            .update_curve_signed_prekey(&new_signed_prekey)
            .map_err(|e| {
                error!("Failed to update signed prekey: {:?}", e);
                GeneralError::StorageError(e)
            })?;
        debug!("Updated signed prekey");

        // Return the signature
        signature
    };

    // Return the message
    let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client.client_uuid);
    msg.new_keys = Some(NewKeys {
        keys_type: NewKeysType::SignedCurvePrekey,
        signed_curve_prekey: Some(SignedCurvePrekey {
            identified_public_key: IdentifiedEllipticCurvePublicKey::from_identified_key_pair(
                &new_signed_prekey,
            ),
            signature,
        }),
        signed_last_resort_pqkem_prekey: None,
        one_time_curve_prekey_set: None,
        signed_one_time_pqkem_prekey_set: None,
    });

    Ok(msg)
}
