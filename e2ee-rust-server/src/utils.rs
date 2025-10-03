use e2ee_rust_common::{
    messages::server::server_message::{ServerCommand, ServerMessage},
    storage::server::{client_structs::ClientKeyBundle, traits::ServerStorage},
};
use log::debug;
use uuid::Uuid;

use crate::{
    CURVE_ONE_TIME_PREKEYS_THRESHOLD, CURVE_SIGNED_PREKEY_LIFETIME_SECS,
    PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS, PQKEM_ONE_TIME_PREKEYS_THRESHOLD,
};

enum KeysCheckResult {
    Ok,
    NewSPK,
    NewLRSPK,
    NewCOPK,
    NewPQOPK,
}

pub fn state_check_keys(
    client_id: Uuid,
    bundle: &ClientKeyBundle,
    server_storage: &impl ServerStorage,
) -> ServerMessage {
    let state = check_keys(bundle);

    match state {
        KeysCheckResult::Ok => state_send_first_messages(client_id, server_storage),
        KeysCheckResult::NewSPK => {
            debug!("Asking for new SPK");
            ServerMessage::new_command(ServerCommand::AskForNewSPK)
        }
        KeysCheckResult::NewLRSPK => {
            debug!("Asking for new last resort PQKEM prekey");
            ServerMessage::new_command(ServerCommand::AskForNewLastResortPQKEMPrekey)
        }
        KeysCheckResult::NewCOPK => {
            debug!("Asking for new curve one time prekeys");
            ServerMessage::new_command(ServerCommand::AskForNewCOPK)
        }
        KeysCheckResult::NewPQOPK => {
            debug!("Asking for new PQKEM one time prekeys");
            ServerMessage::new_command(ServerCommand::AskForNewPQOPK)
        }
    }
}

fn state_send_first_messages(
    _client_id: Uuid,
    _server_storage: &impl ServerStorage,
) -> ServerMessage {
    // TODO: Implement this function
    debug!("Sending first messages");
    ServerMessage::new_ok()
}

fn check_keys(bundle: &ClientKeyBundle) -> KeysCheckResult {
    debug!("Checking keys");
    let now = chrono::Utc::now();

    // Check if the curve signed prekey is expired
    if now
        .signed_duration_since(bundle.signed_curve_prekey.1)
        .as_seconds_f32() as u64
        > CURVE_SIGNED_PREKEY_LIFETIME_SECS
    {
        debug!("Curve signed prekey is expired");
        return KeysCheckResult::NewSPK;
    }

    // Check if the last resort PQKEM signed prekey is expired
    if now
        .signed_duration_since(bundle.signed_last_resort_pqkem_prekey.1)
        .as_seconds_f32() as u64
        > PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS
    {
        debug!("Last resort PQKEM signed prekey is expired");
        return KeysCheckResult::NewLRSPK;
    }

    // Check if we are running low on curve one time prekeys
    if bundle.one_time_curve_prekeys.prekeys.len() < CURVE_ONE_TIME_PREKEYS_THRESHOLD {
        debug!("Running low on curve one time prekeys");
        return KeysCheckResult::NewCOPK;
    }

    // Check if we are running low on PQKEM one time prekeys
    if bundle.signed_one_time_pqkem_prekeys.prekeys.len() < PQKEM_ONE_TIME_PREKEYS_THRESHOLD {
        debug!("Running low on PQKEM one time prekeys");
        return KeysCheckResult::NewPQOPK;
    }

    // All keys are fine
    debug!("All keys are fine");
    return KeysCheckResult::Ok;
}
