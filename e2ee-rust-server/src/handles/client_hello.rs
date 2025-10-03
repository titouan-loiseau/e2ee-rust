use e2ee_rust_common::{
    messages::{
        client::client_hello::ClientHello,
        server::server_message::{ServerCommand, ServerMessage},
    },
    storage::server::traits::ServerStorage,
};
use log::debug;
use uuid::Uuid;

use crate::utils::state_check_keys;

pub fn handle_client_hello(
    client_id: Uuid,
    _client_hello: &ClientHello,
    server_storage: &impl ServerStorage,
) -> ServerMessage {
    debug!("Handling client hello from client_id: {}", client_id);

    // Check if the client is registered
    if let Ok(client_info) = server_storage.get_client(&client_id) {
        // Get the keys and check them
        return state_check_keys(client_id, &client_info.key_bundle, server_storage);
    }

    // Client is not registered, ask for registration bundle
    debug!("Client is not registered, asking for registration bundle");
    return ServerMessage::new_command(ServerCommand::AskForRegistrationBundle);
}
