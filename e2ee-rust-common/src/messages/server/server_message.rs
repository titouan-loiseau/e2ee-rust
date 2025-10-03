use crate::{
    errors::protobuf::ProtobufError,
    messages::server::server_peer_bundle::ServerPeerBundle,
    protobuf::server::{
        pb_server_message, pb_server_message_data::Data, PbServerCommand, PbServerError,
        PbServerMessage, PbServerMessageData,
    },
};

#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessageType {
    Error,
    Command,
    Ok,
    Data,
}

#[derive(Debug, Clone)]
pub enum ServerError {
    UnknownError,
    CannotDecodeClientMessage,
    ClientAlreadyRegistered,
    ClientNotRegistered,
    BadResponse,
}

impl Into<PbServerError> for &ServerError {
    fn into(self) -> PbServerError {
        match self {
            ServerError::UnknownError => PbServerError::UnknownError,
            ServerError::CannotDecodeClientMessage => PbServerError::CannotDecodeClientMessage,
            ServerError::ClientAlreadyRegistered => PbServerError::ClientAlreadyRegistered,
            ServerError::ClientNotRegistered => PbServerError::ClientNotRegistered,
            ServerError::BadResponse => PbServerError::BadResponse,
        }
    }
}

impl ServerError {
    pub fn from_protobuf(pb_server_error: PbServerError) -> ServerError {
        match pb_server_error {
            PbServerError::UnknownError => ServerError::UnknownError,
            PbServerError::CannotDecodeClientMessage => ServerError::CannotDecodeClientMessage,
            PbServerError::ClientAlreadyRegistered => ServerError::ClientAlreadyRegistered,
            PbServerError::ClientNotRegistered => ServerError::ClientNotRegistered,
            PbServerError::BadResponse => ServerError::BadResponse,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServerCommand {
    AskForRegistrationBundle,
    AskForNewSPK,
    AskForNewLastResortPQKEMPrekey,
    AskForNewCOPK,
    AskForNewPQOPK,
}

impl Into<PbServerCommand> for &ServerCommand {
    fn into(self) -> PbServerCommand {
        match self {
            ServerCommand::AskForRegistrationBundle => PbServerCommand::AskForRegistrationBundle,
            ServerCommand::AskForNewSPK => PbServerCommand::AskForNewSpk,
            ServerCommand::AskForNewLastResortPQKEMPrekey => {
                PbServerCommand::AskForNewLastResortPqkemPrekey
            }
            ServerCommand::AskForNewCOPK => PbServerCommand::AskForNewCopk,
            ServerCommand::AskForNewPQOPK => PbServerCommand::AskForNewPqopk,
        }
    }
}

impl ServerCommand {
    pub fn from_protobuf(pb_server_command: PbServerCommand) -> ServerCommand {
        match pb_server_command {
            PbServerCommand::AskForRegistrationBundle => ServerCommand::AskForRegistrationBundle,
            PbServerCommand::AskForNewSpk => ServerCommand::AskForNewSPK,
            PbServerCommand::AskForNewLastResortPqkemPrekey => {
                ServerCommand::AskForNewLastResortPQKEMPrekey
            }
            PbServerCommand::AskForNewCopk => ServerCommand::AskForNewCOPK,
            PbServerCommand::AskForNewPqopk => ServerCommand::AskForNewPQOPK,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServerDataType {
    PeerBundle,
}

#[derive(Debug, Clone)]
pub struct ServerMessageData {
    pub data_type: ServerDataType,
    pub peer_bundle: Option<ServerPeerBundle>,
}

impl ServerMessageData {
    pub fn from_protobuf(
        pb_server_message_data: PbServerMessageData,
    ) -> Result<Self, ProtobufError> {
        match pb_server_message_data.data.unwrap() {
            Data::PeerBundle(pb_server_peer_bundle) => Ok(Self {
                data_type: ServerDataType::PeerBundle,
                peer_bundle: Some(ServerPeerBundle::from_protobuf(&pb_server_peer_bundle)?),
            }),
        }
    }

    pub fn to_protobuf(&self) -> PbServerMessageData {
        let data: Data = match self.data_type {
            ServerDataType::PeerBundle => {
                Data::PeerBundle(self.peer_bundle.as_ref().unwrap().to_protobuf())
            }
        };

        PbServerMessageData { data: Some(data) }
    }
}

#[derive(Debug, Clone)]
pub struct ServerMessage {
    pub message_type: ServerMessageType,
    pub error: Option<ServerError>,
    pub command: Option<ServerCommand>,
    pub data: Option<ServerMessageData>,
}

impl ServerMessage {
    pub fn new_ok() -> Self {
        Self {
            message_type: ServerMessageType::Ok,
            error: None,
            command: None,
            data: None,
        }
    }

    pub fn new_error(error: ServerError) -> Self {
        Self {
            message_type: ServerMessageType::Error,
            error: Some(error),
            command: None,
            data: None,
        }
    }

    pub fn new_command(command: ServerCommand) -> Self {
        Self {
            message_type: ServerMessageType::Command,
            error: None,
            command: Some(command),
            data: None,
        }
    }

    pub fn new_data(data: ServerMessageData) -> Self {
        Self {
            message_type: ServerMessageType::Data,
            error: None,
            command: None,
            data: Some(data),
        }
    }

    pub fn to_protobuf(&self) -> PbServerMessage {
        PbServerMessage {
            message: match self.message_type {
                ServerMessageType::Error => Some(pb_server_message::Message::Error(
                    Into::<PbServerError>::into(self.error.as_ref().unwrap()).into(),
                )),
                ServerMessageType::Command => Some(pb_server_message::Message::Command(
                    Into::<PbServerCommand>::into(self.command.as_ref().unwrap()).into(),
                )),
                ServerMessageType::Ok => Some(pb_server_message::Message::Ok(true)),
                ServerMessageType::Data => Some(pb_server_message::Message::Data(
                    self.data.as_ref().unwrap().to_protobuf(),
                )),
            },
        }
    }
}
