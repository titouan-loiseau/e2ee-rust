use crate::{
    crypto::pqkem::{
        enum_pqkem_type::PQKEMType,
        keys::{IdentifiedPQKEMPublicKey, PQKEMPublicKey},
    },
    errors::protobuf::ProtobufError,
    protobuf::{pqxdh::PbSignedPqkemPrekey, utils::uuid_from_bytes},
};

#[derive(Clone, Debug)]
pub struct SignedPQKEMPrekey {
    pub identified_public_key: IdentifiedPQKEMPublicKey,
    pub signature: [u8; 64],
}

impl SignedPQKEMPrekey {
    pub fn to_protobuf(&self) -> PbSignedPqkemPrekey {
        PbSignedPqkemPrekey {
            signature: self.signature.as_slice().to_vec(),
            identified_public_key: Some(self.identified_public_key.to_protobuf()),
        }
    }

    pub fn from_protobuf(
        pb_signed_pqkem_prekey: &PbSignedPqkemPrekey,
    ) -> Result<Self, ProtobufError> {
        let pb_signed_pqkem_prekey = pb_signed_pqkem_prekey.clone();
        let pb_identified_pqkem_public_key = pb_signed_pqkem_prekey
            .identified_public_key
            .ok_or(ProtobufError::MissingField("identified_public_key"))?;
        let pb_pqkem_public_key =
            pb_identified_pqkem_public_key
                .public_key
                .ok_or(ProtobufError::MissingField(
                    "identified_public_key.public_key",
                ))?;
        let pqkem_prekey_type = PQKEMType::from_id(pb_pqkem_public_key.key_type as u8).ok_or(
            ProtobufError::InvalidField("identified_public_key.public_key.key_type"),
        )?;
        let pqkem_prekey_bytes = pb_pqkem_public_key.key_bytes;
        if pqkem_prekey_bytes.len() != pqkem_prekey_type.public_key_length() {
            return Err(ProtobufError::InvalidFieldLength(
                "identified_public_key.public_key.key_bytes",
                pqkem_prekey_bytes.len(),
                pqkem_prekey_type.public_key_length(),
            ));
        }

        let pb_pqkem_prekey_signature = pb_signed_pqkem_prekey.signature;
        let pb_pqkem_prekey_signature_len = pb_pqkem_prekey_signature.len();
        let pqkem_prekey_signature_bytes: [u8; 64] =
            pb_pqkem_prekey_signature.try_into().map_err(|_| {
                ProtobufError::InvalidFieldLength("signature", pb_pqkem_prekey_signature_len, 64)
            })?;

        Ok(Self {
            identified_public_key: IdentifiedPQKEMPublicKey {
                id: uuid_from_bytes(&pb_identified_pqkem_public_key.uuid)?,
                public_key: PQKEMPublicKey {
                    key_type: pqkem_prekey_type,
                    bytes: pqkem_prekey_bytes,
                },
            },
            signature: pqkem_prekey_signature_bytes,
        })
    }
}
