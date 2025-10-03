use uuid::Uuid;

use crate::{errors::protobuf::ProtobufError, protobuf::client::PbClientRequestPeerBundle};

pub struct RequestPeerBundle {
    pub peer_uuid: Uuid,
}

impl RequestPeerBundle {
    pub fn to_protobuf(&self) -> PbClientRequestPeerBundle {
        PbClientRequestPeerBundle {
            peer_uuid: self.peer_uuid.to_string(),
        }
    }

    pub fn from_protobuf(
        pb_client_request_peer_bundle: &PbClientRequestPeerBundle,
    ) -> Result<Self, ProtobufError> {
        Ok(Self {
            peer_uuid: Uuid::parse_str(&pb_client_request_peer_bundle.peer_uuid)
                .map_err(|_| ProtobufError::InvalidField("peer_uuid"))?,
        })
    }
}
