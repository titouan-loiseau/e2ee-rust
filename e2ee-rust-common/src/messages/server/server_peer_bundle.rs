use crate::{
    crypto::curve::keys::{EllipticCurvePublicKey, IdentifiedEllipticCurvePublicKey},
    errors::protobuf::ProtobufError,
    pqxdh::{
        prekey_bundle::PrekeyBundle, signed_curve_prekey::SignedCurvePrekey,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    protobuf::server::PbServerPeerBundle,
};

#[derive(Clone, Debug)]
pub struct ServerPeerBundle {
    pub bundle: PrekeyBundle,
}

impl ServerPeerBundle {
    pub fn from_protobuf(
        pb_server_peer_bundle: &PbServerPeerBundle,
    ) -> Result<Self, ProtobufError> {
        let pb_identity_key = pb_server_peer_bundle
            .identity_key
            .as_ref()
            .ok_or(ProtobufError::MissingField("identified_public_key"))?;

        let pb_signed_curve_prekey = pb_server_peer_bundle
            .signed_curve_prekey
            .as_ref()
            .ok_or(ProtobufError::MissingField("signed_curve_prekey"))?;

        let pb_signed_pqkem_prekey = pb_server_peer_bundle
            .signed_pqkem_prekey
            .as_ref()
            .ok_or(ProtobufError::MissingField("signed_pqkem_prekey"))?;

        let one_time_curve_prekey: Option<IdentifiedEllipticCurvePublicKey> =
            match pb_server_peer_bundle.one_time_curve_prekey.as_ref() {
                Some(pb_one_time_curve_prekey) => Some(
                    IdentifiedEllipticCurvePublicKey::from_protobuf(pb_one_time_curve_prekey)?,
                ),
                None => None,
            };

        Ok(ServerPeerBundle {
            bundle: PrekeyBundle {
                identity_key: EllipticCurvePublicKey::from_protobuf(&pb_identity_key)?,
                signed_curve_prekey: SignedCurvePrekey::from_protobuf(&pb_signed_curve_prekey)?,
                one_time_pqkem_prekey: SignedPQKEMPrekey::from_protobuf(&pb_signed_pqkem_prekey)?,
                one_time_curve_prekey,
            },
        })
    }

    pub fn to_protobuf(&self) -> PbServerPeerBundle {
        PbServerPeerBundle {
            identity_key: Some(self.bundle.identity_key.to_protobuf()),
            signed_curve_prekey: Some(self.bundle.signed_curve_prekey.to_protobuf()),
            signed_pqkem_prekey: Some(self.bundle.one_time_pqkem_prekey.to_protobuf()),
            one_time_curve_prekey: self
                .bundle
                .one_time_curve_prekey
                .as_ref()
                .map(|key| key.to_protobuf()),
        }
    }
}
