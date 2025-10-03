use crate::{
    crypto::curve::{
        enum_elliptic_curve_type::EllipticCurveType,
        keys::{EllipticCurvePublicKey, IdentifiedEllipticCurvePublicKey},
    },
    errors::protobuf::ProtobufError,
    protobuf::{pqxdh::PbSignedCurvePrekey, utils::uuid_from_bytes},
};

#[derive(Clone, Debug)]
pub struct SignedCurvePrekey {
    pub identified_public_key: IdentifiedEllipticCurvePublicKey,
    pub signature: [u8; 64],
}

impl SignedCurvePrekey {
    pub fn to_protobuf(&self) -> PbSignedCurvePrekey {
        PbSignedCurvePrekey {
            identified_public_key: Some(self.identified_public_key.to_protobuf()),
            signature: self.signature.to_vec(),
        }
    }

    pub fn from_protobuf(
        pb_signed_curve_prekey: &PbSignedCurvePrekey,
    ) -> Result<Self, ProtobufError> {
        let pb_signed_curve_prekey = pb_signed_curve_prekey.clone();

        let pb_curve_prekey = pb_signed_curve_prekey
            .identified_public_key
            .ok_or(ProtobufError::MissingField("identified_public_key"))?;
        let pb_curve_prekey_public_key =
            pb_curve_prekey
                .public_key
                .ok_or(ProtobufError::MissingField(
                    "identified_public_key.public_key",
                ))?;
        let curve_prekey_public_key_type: EllipticCurveType =
            EllipticCurveType::from_id(pb_curve_prekey_public_key.key_type as u8).ok_or(
                ProtobufError::InvalidField("identified_public_key.public_key.key_type"),
            )?;
        let curve_prekey_public_key_bytes = pb_curve_prekey_public_key.key_bytes;
        if curve_prekey_public_key_bytes.len() != curve_prekey_public_key_type.public_key_length() {
            return Err(ProtobufError::InvalidFieldLength(
                "identified_public_key.public_key.key_bytes",
                curve_prekey_public_key_bytes.len(),
                curve_prekey_public_key_type.public_key_length(),
            ));
        }

        let pb_curve_prekey_signature = pb_signed_curve_prekey.signature;
        let pb_curve_prekey_signature_len = pb_curve_prekey_signature.len();
        let curve_prekey_signature_bytes: [u8; 64] =
            pb_curve_prekey_signature.try_into().map_err(|_| {
                ProtobufError::InvalidFieldLength("signature", pb_curve_prekey_signature_len, 64)
            })?;

        Ok(Self {
            identified_public_key: IdentifiedEllipticCurvePublicKey {
                id: uuid_from_bytes(&pb_curve_prekey.uuid)?,
                public_key: EllipticCurvePublicKey {
                    key_type: curve_prekey_public_key_type,
                    bytes: curve_prekey_public_key_bytes,
                },
            },
            signature: curve_prekey_signature_bytes,
        })
    }
}
