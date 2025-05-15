use crate::{
    crypto::curve::{
        enum_elliptic_curve_type::EllipticCurveType,
        keys::{EllipticCurvePublicKey, IdentifiedEllipticCurvePublicKey},
    },
    errors::protobuf::ProtobufError,
    protobuf::{pqxdh::PbOneTimeCurvePrekeySet, utils::uuid_from_bytes},
};

#[derive(Clone)]
pub struct OneTimeCurvePrekeySet {
    pub prekeys: Vec<IdentifiedEllipticCurvePublicKey>,
}

impl OneTimeCurvePrekeySet {
    pub fn to_protobuf(&self) -> PbOneTimeCurvePrekeySet {
        PbOneTimeCurvePrekeySet {
            prekeys: self.prekeys.iter().map(|p| p.to_protobuf()).collect(),
        }
    }

    pub fn from_protobuf(
        pb_one_time_curve_prekeys: &PbOneTimeCurvePrekeySet,
    ) -> Result<Self, ProtobufError> {
        let pb_one_time_curve_prekeys = pb_one_time_curve_prekeys.clone();
        let one_time_curve_prekeys: Vec<IdentifiedEllipticCurvePublicKey> =
            pb_one_time_curve_prekeys
                .prekeys
                .into_iter()
                .map(|pb_one_time_curve_prekey| {
                    let pb_one_time_curve_prekey_public_key = pb_one_time_curve_prekey
                        .public_key
                        .ok_or(
                        ProtobufError::MissingField("one_time_curve_prekeys.public_key"),
                    )?;
                    let one_time_curve_prekey_public_key_type = EllipticCurveType::from_id(
                        pb_one_time_curve_prekey_public_key.key_type as u8,
                    )
                    .ok_or(ProtobufError::InvalidField(
                        "one_time_curve_prekeys.public_key.key_type",
                    ))?;
                    let one_time_curve_prekey_public_key_bytes =
                        pb_one_time_curve_prekey_public_key.key_bytes;
                    if one_time_curve_prekey_public_key_bytes.len()
                        != one_time_curve_prekey_public_key_type.public_key_length()
                    {
                        return Err(ProtobufError::InvalidFieldLength(
                            "one_time_curve_prekeys.public_key.key_bytes",
                            one_time_curve_prekey_public_key_bytes.len(),
                            one_time_curve_prekey_public_key_type.public_key_length(),
                        ));
                    }
                    Ok(IdentifiedEllipticCurvePublicKey {
                        id: uuid_from_bytes(&pb_one_time_curve_prekey.uuid)?,
                        public_key: EllipticCurvePublicKey {
                            key_type: one_time_curve_prekey_public_key_type,
                            bytes: one_time_curve_prekey_public_key_bytes,
                        },
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            prekeys: one_time_curve_prekeys,
        })
    }
}
