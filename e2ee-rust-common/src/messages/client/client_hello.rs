use crate::{errors::protobuf::ProtobufError, protobuf::client::PbClientHello};

pub struct ClientHello {}

impl ClientHello {
    pub fn from_protobuf(_pb_client_hello: PbClientHello) -> Result<Self, ProtobufError> {
        Ok(Self {})
    }

    pub fn to_protobuf(&self) -> PbClientHello {
        PbClientHello {}
    }
}
