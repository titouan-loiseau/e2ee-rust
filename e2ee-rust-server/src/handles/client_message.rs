use e2ee_rust_common::{
    messages::{
        client::client_message::{ClientMessage, ClientMessageType},
        server::server_message::ServerMessage,
    },
    storage::server::traits::ServerStorage,
};

use super::{
    client_hello::handle_client_hello, new_keys::handle_new_keys,
    registration_bundle::handle_registration_bundle,
    request_peer_bundle::handle_request_peer_bundle,
};

pub fn handle_client_message(
    client_message: &ClientMessage,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    match client_message.message_type {
        ClientMessageType::ClientHello => {
            let client_hello = client_message.client_hello.as_ref().unwrap();
            handle_client_hello(client_message.client_id, client_hello, server_storage)
        }
        ClientMessageType::RegistrationBundle => {
            let registration_bundle = client_message.registration_bundle.as_ref().unwrap();
            handle_registration_bundle(
                client_message.client_id,
                registration_bundle,
                server_storage,
            )
        }
        ClientMessageType::NewKeys => {
            let new_keys = client_message.new_keys.as_ref().unwrap();
            handle_new_keys(client_message.client_id, new_keys, server_storage)
        }
        ClientMessageType::RequestPeerBundle => {
            let request_peer_bundle = client_message.request_peer_bundle.as_ref().unwrap();
            handle_request_peer_bundle(request_peer_bundle, server_storage)
        }
    }
}
