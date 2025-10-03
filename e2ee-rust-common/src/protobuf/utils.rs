use prost::Message;
use uuid::Uuid;

use crate::{
    errors::protobuf::ProtobufError,
    messages::{
        client::{
            client_hello::ClientHello,
            client_message::{ClientMessage, ClientMessageType},
            new_keys::NewKeys,
            request_peer_bundle::RequestPeerBundle,
        },
        server::server_message::{ServerCommand, ServerError, ServerMessage, ServerMessageData},
    },
    pqxdh::registration_bundle::RegistrationBundle,
    protobuf::server::PbServerMessageData,
};

use super::{
    client::{pb_client_message, PbClientMessage},
    server::{pb_server_message, PbServerCommand, PbServerError, PbServerMessage},
};

pub fn uuid_from_bytes(bytes: &[u8]) -> Result<Uuid, ProtobufError> {
    Uuid::from_slice(bytes).map_err(|_| ProtobufError::WrongBufferSize)
}

pub fn uuid_from_str(str: &str) -> Result<Uuid, ProtobufError> {
    Uuid::parse_str(str).map_err(|_| ProtobufError::WrongBufferSize)
}

pub fn decode_client_message(data: &[u8]) -> Result<ClientMessage, ProtobufError> {
    let pb_client_msg: PbClientMessage =
        PbClientMessage::decode(data).map_err(|e| ProtobufError::DecodeError(e))?;

    let client_id = uuid_from_str(&pb_client_msg.client_id)?;

    match pb_client_msg
        .message
        .ok_or(ProtobufError::MissingMessageType)?
    {
        pb_client_message::Message::ClientHello(pb_client_hello) => {
            let mut client_message = ClientMessage::new(ClientMessageType::ClientHello, client_id);
            client_message.client_hello = Some(ClientHello::from_protobuf(pb_client_hello)?);
            Ok(client_message)
        }
        pb_client_message::Message::RegistrationBundle(pb_registration_bundle) => {
            let mut client_message =
                ClientMessage::new(ClientMessageType::RegistrationBundle, client_id);
            client_message.registration_bundle =
                Some(RegistrationBundle::from_protobuf(pb_registration_bundle)?);
            Ok(client_message)
        }
        pb_client_message::Message::NewKeys(pb_new_keys) => {
            let mut client_message = ClientMessage::new(ClientMessageType::NewKeys, client_id);
            client_message.new_keys = Some(NewKeys::from_protobuf(&pb_new_keys)?);
            Ok(client_message)
        }
        pb_client_message::Message::RequestPeerBundle(pb_request_peer_bundle) => {
            let mut client_message =
                ClientMessage::new(ClientMessageType::RequestPeerBundle, client_id);
            client_message.request_peer_bundle =
                Some(RequestPeerBundle::from_protobuf(&pb_request_peer_bundle)?);
            Ok(client_message)
        }
    }
}

pub fn decode_server_message(data: &[u8]) -> Result<ServerMessage, ProtobufError> {
    let pb_server_msg: PbServerMessage =
        PbServerMessage::decode(data).map_err(|e| ProtobufError::DecodeError(e))?;

    match pb_server_msg
        .message
        .ok_or(ProtobufError::MissingMessageType)?
    {
        pb_server_message::Message::Error(pb_server_error) => {
            Ok(ServerMessage::new_error(ServerError::from_protobuf(
                PbServerError::try_from(pb_server_error).map_err(|e| {
                    ProtobufError::DecodeError(prost::DecodeError::new(e.to_string()))
                })?,
            )))
        }
        pb_server_message::Message::Command(pb_server_command) => {
            Ok(ServerMessage::new_command(ServerCommand::from_protobuf(
                PbServerCommand::try_from(pb_server_command).map_err(|e| {
                    ProtobufError::DecodeError(prost::DecodeError::new(e.to_string()))
                })?,
            )))
        }
        pb_server_message::Message::Ok(_) => Ok(ServerMessage::new_ok()),
        pb_server_message::Message::Data(pb_server_message_data) => {
            Ok(ServerMessage::new_data(ServerMessageData::from_protobuf(
                PbServerMessageData::try_from(pb_server_message_data).map_err(|e| {
                    ProtobufError::DecodeError(prost::DecodeError::new(e.to_string()))
                })?,
            )?))
        }
    }
}

pub fn create_client_message(client_message: &ClientMessage) -> Vec<u8> {
    client_message.to_protobuf().encode_to_vec()
}

pub fn create_server_message(server_message: &ServerMessage) -> Vec<u8> {
    server_message.to_protobuf().encode_to_vec()
}
