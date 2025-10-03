use uuid::Uuid;

use crate::pqxdh::registration_bundle::RegistrationBundle;

use crate::protobuf::client::{pb_client_message, PbClientMessage};

use super::client_hello::ClientHello;
use super::new_keys::NewKeys;
use super::request_peer_bundle::RequestPeerBundle;

pub struct ClientMessage {
    pub message_type: ClientMessageType,
    pub client_id: Uuid,
    pub client_hello: Option<ClientHello>,
    pub registration_bundle: Option<RegistrationBundle>,
    pub new_keys: Option<NewKeys>,
    pub request_peer_bundle: Option<RequestPeerBundle>,
}

impl ClientMessage {
    pub fn new(message_type: ClientMessageType, client_id: Uuid) -> Self {
        Self {
            message_type,
            client_id,
            client_hello: None,
            registration_bundle: None,
            new_keys: None,
            request_peer_bundle: None,
        }
    }

    pub fn to_protobuf(&self) -> PbClientMessage {
        PbClientMessage {
            client_id: self.client_id.to_string(),
            message: match self.message_type {
                ClientMessageType::ClientHello => Some(pb_client_message::Message::ClientHello(
                    self.client_hello.as_ref().unwrap().to_protobuf(),
                )),
                ClientMessageType::RegistrationBundle => {
                    Some(pb_client_message::Message::RegistrationBundle(
                        self.registration_bundle.as_ref().unwrap().to_protobuf(),
                    ))
                }
                ClientMessageType::NewKeys => Some(pb_client_message::Message::NewKeys(
                    self.new_keys.as_ref().unwrap().to_protobuf(),
                )),
                ClientMessageType::RequestPeerBundle => {
                    Some(pb_client_message::Message::RequestPeerBundle(
                        self.request_peer_bundle.as_ref().unwrap().to_protobuf(),
                    ))
                }
            },
        }
    }
}

pub enum ClientMessageType {
    ClientHello,
    RegistrationBundle,
    NewKeys,
    RequestPeerBundle,
}
