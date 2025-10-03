use e2ee_rust_common::{
    messages::server::server_message::{ServerError, ServerMessage},
    pqxdh::registration_bundle::RegistrationBundle,
    storage::server::{
        client_structs::{ClientInformation, ClientKeyBundle},
        traits::ServerStorage,
    },
};
use log::{debug, error};
use uuid::Uuid;

use crate::utils::state_check_keys;

pub fn handle_registration_bundle(
    client_id: Uuid,
    registration_bundle: &RegistrationBundle,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    debug!("Handling registration bundle");

    // Make sure that the client is not already registered
    if server_storage.get_client(&client_id).is_ok() {
        return ServerMessage::new_error(ServerError::ClientAlreadyRegistered);
    }

    // Create the client key bundle
    let now = chrono::Utc::now();
    let client_key_bundle = ClientKeyBundle {
        identity_key: (registration_bundle.identity_key.clone(), now),
        signed_curve_prekey: (registration_bundle.signed_curve_prekey.clone(), now),
        signed_last_resort_pqkem_prekey: (
            registration_bundle.signed_last_resort_pqkem_prekey.clone(),
            now,
        ),
        one_time_curve_prekeys: registration_bundle.one_time_curve_prekeys.clone(),
        signed_one_time_pqkem_prekeys: registration_bundle.one_time_pqkem_prekeys.clone(),
    };

    // Add the client to the server storage
    if let Err(e) = server_storage.add_client(
        client_id,
        &ClientInformation {
            key_bundle: client_key_bundle.clone(),
        },
    ) {
        error!("Error adding client: {:?}", e);
        return ServerMessage::new_error(ServerError::UnknownError);
    }

    // Check the keys
    state_check_keys(client_id, &client_key_bundle, server_storage)
}
