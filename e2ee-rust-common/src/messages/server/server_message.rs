use crate::protobuf::server::{pb_server_message, PbServerCommand, PbServerError, PbServerMessage};

#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessageType {
    Error,
    Command,
    Ok,
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
pub struct ServerMessage {
    pub message_type: ServerMessageType,
    pub error: Option<ServerError>,
    pub command: Option<ServerCommand>,
}

impl ServerMessage {
    pub fn new_ok() -> Self {
        Self {
            message_type: ServerMessageType::Ok,
            error: None,
            command: None,
        }
    }

    pub fn new_error(error: ServerError) -> Self {
        Self {
            message_type: ServerMessageType::Error,
            error: Some(error),
            command: None,
        }
    }

    pub fn new_command(command: ServerCommand) -> Self {
        Self {
            message_type: ServerMessageType::Command,
            error: None,
            command: Some(command),
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
            },
        }
    }
}
