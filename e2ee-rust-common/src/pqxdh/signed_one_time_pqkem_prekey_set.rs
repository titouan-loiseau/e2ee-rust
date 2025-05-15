use crate::{
    crypto::pqkem::{
        enum_pqkem_type::PQKEMType,
        keys::{IdentifiedPQKEMPublicKey, PQKEMPublicKey},
    },
    errors::protobuf::ProtobufError,
    protobuf::{pqxdh::PbSignedOneTimePqkemPrekeySet, utils::uuid_from_bytes},
};

use super::signed_pqkem_prekey::SignedPQKEMPrekey;

#[derive(Clone)]
pub struct SignedOneTimePqkemPrekeySet {
    pub prekeys: Vec<SignedPQKEMPrekey>,
}

impl SignedOneTimePqkemPrekeySet {
    pub fn to_protobuf(&self) -> PbSignedOneTimePqkemPrekeySet {
        PbSignedOneTimePqkemPrekeySet {
            prekeys: self.prekeys.iter().map(|p| p.to_protobuf()).collect(),
        }
    }

    pub fn from_protobuf(
        pb_signed_one_time_pqkem_prekeys: &PbSignedOneTimePqkemPrekeySet,
    ) -> Result<Self, ProtobufError> {
        let pb_signed_one_time_pqkem_prekeys = pb_signed_one_time_pqkem_prekeys.clone();
        let one_time_pqkem_prekeys: Vec<SignedPQKEMPrekey> = pb_signed_one_time_pqkem_prekeys
            .prekeys
            .into_iter()
            .map(|pb_one_time_pqkem_prekey| {
                let pb_one_time_pqkem_prekey_identified_public_key =
                    pb_one_time_pqkem_prekey.identified_public_key.ok_or(
                        ProtobufError::MissingField("one_time_pqkem_prekeys.identified_public_key"),
                    )?;
                let pb_one_time_pqkem_prekey_public_key =
                    pb_one_time_pqkem_prekey_identified_public_key
                        .public_key
                        .ok_or(ProtobufError::MissingField(
                            "one_time_pqkem_prekeys.identified_public_key.public_key",
                        ))?;
                let one_time_pqkem_prekey_public_key_type = PQKEMType::from_id(
                    pb_one_time_pqkem_prekey_public_key.key_type as u8,
                )
                .ok_or(ProtobufError::InvalidField(
                    "one_time_pqkem_prekeys.identified_public_key.public_key.key_type",
                ))?;
                let one_time_pqkem_prekey_public_key_bytes =
                    pb_one_time_pqkem_prekey_public_key.key_bytes;
                if one_time_pqkem_prekey_public_key_bytes.len()
                    != one_time_pqkem_prekey_public_key_type.public_key_length()
                {
                    return Err(ProtobufError::InvalidFieldLength(
                        "one_time_pqkem_prekeys.identified_public_key.public_key.key_bytes",
                        one_time_pqkem_prekey_public_key_bytes.len(),
                        one_time_pqkem_prekey_public_key_type.public_key_length(),
                    ));
                }
                let pb_one_time_pqkem_prekey_signature_bytes = pb_one_time_pqkem_prekey.signature;
                let pb_one_time_pqkem_prekey_signature_bytes_len =
                    pb_one_time_pqkem_prekey_signature_bytes.len();
                let one_time_pqkem_prekey_signature_bytes: [u8; 64] =
                    pb_one_time_pqkem_prekey_signature_bytes
                        .try_into()
                        .map_err(|_| {
                            ProtobufError::InvalidFieldLength(
                                "one_time_pqkem_prekeys.signature",
                                pb_one_time_pqkem_prekey_signature_bytes_len,
                                64,
                            )
                        })?;

                Ok(SignedPQKEMPrekey {
                    identified_public_key: IdentifiedPQKEMPublicKey {
                        id: uuid_from_bytes(&pb_one_time_pqkem_prekey_identified_public_key.uuid)?,
                        public_key: PQKEMPublicKey {
                            key_type: one_time_pqkem_prekey_public_key_type,
                            bytes: one_time_pqkem_prekey_public_key_bytes,
                        },
                    },
                    signature: one_time_pqkem_prekey_signature_bytes,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            prekeys: one_time_pqkem_prekeys,
        })
    }
}
