use std::sync::Arc;

use e2ee_rust_common::{
    crypto::{curve::traits::EllipticCurveAlgorithm, pqkem::traits::PQKEMAlgorithm},
    errors::general::{GeneralError, ToGeneralError},
    messages::client::client_message::{ClientMessage, ClientMessageType},
    pqxdh::registration_bundle::RegistrationBundle,
    storage::client::traits::ClientStorage,
};
use rand::{CryptoRng, RngCore};

use crate::ClientData;

pub fn command_ask_for_registration_bundle<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
    R: RngCore + CryptoRng,
>(
    client: &Arc<ClientData<T, U, S>>,
    rng: &mut R,
) -> Result<ClientMessage, GeneralError> {
    // Create the Client Message
    let mut msg = ClientMessage::new(ClientMessageType::RegistrationBundle, client.client_uuid);

    // Get the private key bundle
    let private_bundle = {
        // Lock the client storage
        let client_storage = client.client_storage_mutex.lock().unwrap();
        client_storage.get_private_key_bundle().to_general_error()?
    };

    // Create the registration bundle
    msg.registration_bundle = Some(RegistrationBundle::from_private_bundle(
        &private_bundle,
        &client.curve_algorithm,
        rng,
    )?);

    // Return message
    Ok(msg)
}
