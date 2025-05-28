use std::sync::Arc;

use e2ee_rust_common::{
    crypto::{curve::traits::EllipticCurveAlgorithm, pqkem::traits::PQKEMAlgorithm},
    errors::general::GeneralError,
    messages::{client::client_message::ClientMessage, server::server_message::ServerCommand},
    storage::client::traits::ClientStorage,
};
use log::debug;

use crate::{
    commands::{
        ask_for_new_curve_onetime_prekeys::command_ask_for_new_curve_onetime_prekeys,
        ask_for_new_last_resort_pqkem_prekey::command_ask_for_new_last_resort_pqkem_prekey,
        ask_for_new_signed_pqkem_onetime_prekeys::command_ask_for_new_signed_pqkem_onetime_prekeys,
        ask_for_new_signed_prekey::command_ask_for_new_signed_prekey,
        ask_for_registration_bundle::command_ask_for_registration_bundle,
    },
    ClientData,
};

pub fn handle_server_command<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
>(
    server_command: &ServerCommand,
    client: &Arc<ClientData<T, U, S>>,
) -> Result<ClientMessage, GeneralError> {
    debug!("Handling server command: {:?}", server_command);
    let mut rng = rand::thread_rng();

    match server_command {
        ServerCommand::AskForRegistrationBundle => {
            debug!("Generating registration bundle from private bundle");
            command_ask_for_registration_bundle(client, &mut rng)
        }
        ServerCommand::AskForNewSPK => {
            debug!("Generating new signed prekey");
            command_ask_for_new_signed_prekey(client, &mut rng)
        }
        ServerCommand::AskForNewCOPK => {
            debug!("Generating new one time curve prekeys");
            command_ask_for_new_curve_onetime_prekeys(client, &mut rng)
        }
        ServerCommand::AskForNewLastResortPQKEMPrekey => {
            debug!("Generating new signed last resort pqkem prekey");
            command_ask_for_new_last_resort_pqkem_prekey(client, &mut rng)
        }
        ServerCommand::AskForNewPQOPK => {
            debug!("Generating new set of signed pqkem prekeys");
            command_ask_for_new_signed_pqkem_onetime_prekeys(client, &mut rng)
        }
    }
}
