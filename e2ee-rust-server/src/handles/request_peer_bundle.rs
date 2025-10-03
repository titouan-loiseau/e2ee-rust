use e2ee_rust_common::{
    messages::{
        client::request_peer_bundle::RequestPeerBundle,
        server::{
            server_message::{
                ServerDataType, ServerError, ServerMessage, ServerMessageData, ServerMessageType,
            },
            server_peer_bundle::ServerPeerBundle,
        },
    },
    pqxdh::prekey_bundle::PrekeyBundle,
    storage::server::{client_structs::ClientKeyBundle, traits::ServerStorage},
};

pub fn handle_request_peer_bundle(
    request_peer_bundle: &RequestPeerBundle,
    server_storage: &impl ServerStorage,
) -> ServerMessage {
    // Get the peer UUID from the request
    let peer_uuid = request_peer_bundle.peer_uuid;

    // Make sure that the peer is registered
    let peer_bundle: ClientKeyBundle;

    // Get the peer bundle as mut
    match server_storage.get_client(&peer_uuid) {
        Ok(client) => peer_bundle = client.key_bundle,
        Err(_) => return ServerMessage::new_error(ServerError::ClientNotRegistered),
    }

    // Try to pop a signed one time pqkem prekey from the peer bundle
    let signed_one_time_pqkem_prekey_opt =
        match server_storage.pop_signed_one_time_pqkem_prekey(peer_uuid) {
            Ok(prekey) => prekey,
            Err(_) => return ServerMessage::new_error(ServerError::UnknownError),
        };
    // If a signed one time pqkem prekey was found, use it, otherwise use the last resort prekey
    let pqkem_prekey = match signed_one_time_pqkem_prekey_opt {
        Some(signed_one_time_pqkem_prekey) => signed_one_time_pqkem_prekey,
        None => peer_bundle.signed_last_resort_pqkem_prekey.0,
    };

    // Try to pop a curve prekey from the peer bundle
    let curve_prekey = match server_storage.pop_one_time_curve_prekey(peer_uuid) {
        Ok(prekey) => prekey,
        Err(_) => return ServerMessage::new_error(ServerError::UnknownError),
    };

    let server_message_data = ServerMessageData {
        data_type: ServerDataType::PeerBundle,
        peer_bundle: Some(ServerPeerBundle {
            bundle: PrekeyBundle {
                identity_key: peer_bundle.identity_key.0,
                signed_curve_prekey: peer_bundle.signed_curve_prekey.0,
                one_time_pqkem_prekey: pqkem_prekey,
                one_time_curve_prekey: curve_prekey,
            },
        }),
    };

    ServerMessage {
        message_type: ServerMessageType::Data,
        error: None,
        command: None,
        data: Some(server_message_data),
    }
}
