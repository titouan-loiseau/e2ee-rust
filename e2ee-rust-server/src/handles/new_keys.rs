use e2ee_rust_common::{
    messages::{
        client::new_keys::{NewKeys, NewKeysType},
        server::server_message::{ServerError, ServerMessage},
    },
    storage::server::{client_structs::ClientInformation, traits::ServerStorage},
};
use log::{debug, error};
use uuid::Uuid;

use crate::utils::state_check_keys;

pub fn handle_new_keys(
    client_id: Uuid,
    new_keys: &NewKeys,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    debug!("Handling new keys");

    // Make sure that the client is registered
    let client_bundle: ClientInformation;

    // Get the client bundle as mut
    match server_storage.get_client(&client_id) {
        Ok(client) => client_bundle = client,
        Err(_) => return ServerMessage::new_error(ServerError::ClientNotRegistered),
    }

    // Update the keys as needed
    let now = chrono::Utc::now();
    let res: Result<(), ServerError> = match new_keys.keys_type {
        NewKeysType::SignedCurvePrekey => {
            debug!("Updating the signed curve prekey");
            if let Some(new_key) = &new_keys.signed_curve_prekey {
                server_storage
                    .update_signed_curve_prekey(client_id, new_key, &now)
                    .map_err(|e| {
                        error!(
                            "Error updating the key bundle's signed curve prekey: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::SignedLastResortPQKEMPrekey => {
            debug!("Updating the last resort PQKEM prekey");
            if let Some(new_key) = &new_keys.signed_last_resort_pqkem_prekey {
                server_storage
                    .update_signed_last_resort_pqkem_prekey(client_id, new_key, &now)
                    .map_err(|e| {
                        error!(
                            "Error updating the key bundle's signed last resort PQKEM prekey: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::OneTimeCurvePrekeySet => {
            debug!("Adding new one time curve prekeys");
            if let Some(new_keys) = &new_keys.one_time_curve_prekey_set {
                server_storage
                    .add_one_time_curve_prekeys(client_id, new_keys)
                    .map_err(|e| {
                        error!(
                            "Error adding one time curve prekeys to the key bundle: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::SignedOneTimePQKEMPrekeySet => {
            debug!("Adding new signed one time PQKEM prekeys");
            if let Some(new_keys) = &new_keys.signed_one_time_pqkem_prekey_set {
                server_storage
                    .add_signed_one_time_pqkem_prekeys(client_id, new_keys)
                    .map_err(|e| {
                        error!(
                            "Error adding signed one time PQKEM prekeys to the key bundle: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
    };
    if let Err(err) = res {
        return ServerMessage::new_error(err);
    }
    debug!("Update OK");

    state_check_keys(client_id, &client_bundle.key_bundle, server_storage)
}
