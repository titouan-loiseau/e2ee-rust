use log::debug;
use rand::{CryptoRng, RngCore};

use crate::{
    crypto::{
        curve::{
            enum_elliptic_curve_type::EllipticCurveType,
            keys::{EllipticCurvePublicKey, IdentifiedEllipticCurvePublicKey},
            traits::EllipticCurveAlgorithm,
        },
        pqkem::keys::IdentifiedPQKEMPublicKey,
    },
    errors::{general::GeneralError, protobuf::ProtobufError},
    protobuf::{
        crypto::{
            curve::{PbEllipticCurvePublicKey, PbIdentifiedEllipticCurvePublicKey},
            pqkem::{PbIdentifiedPqkemPublicKey, PbpqkemPublicKey},
        },
        pqxdh::{
            PbOneTimeCurvePrekeySet, PbRegistrationBundle, PbSignedCurvePrekey,
            PbSignedOneTimePqkemPrekeySet, PbSignedPqkemPrekey,
        },
    },
    utils::display::print_slice,
};

use super::{
    one_time_curve_prekey_set::OneTimeCurvePrekeySet, private_bundle::PrivateBundle,
    signed_curve_prekey::SignedCurvePrekey,
    signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
    signed_pqkem_prekey::SignedPQKEMPrekey,
};

#[derive(Clone)]
pub struct RegistrationBundle {
    pub identity_key: EllipticCurvePublicKey,
    pub signed_curve_prekey: SignedCurvePrekey,
    pub signed_last_resort_pqkem_prekey: SignedPQKEMPrekey,
    pub one_time_curve_prekeys: OneTimeCurvePrekeySet,
    pub one_time_pqkem_prekeys: SignedOneTimePqkemPrekeySet,
}

impl RegistrationBundle {
    pub fn print(&self) {
        debug!("identity_key: {}", self.identity_key.print_key());
        debug!(
            "curve_prekey: {}, {}",
            self.signed_curve_prekey.identified_public_key.id,
            self.signed_curve_prekey
                .identified_public_key
                .public_key
                .print_key()
        );
        debug!(
            "curve_prekey_signature: {}",
            print_slice(&self.signed_curve_prekey.signature)
        );
        debug!(
            "last_resort_prekey: {}, {}",
            self.signed_last_resort_pqkem_prekey
                .identified_public_key
                .id,
            self.signed_last_resort_pqkem_prekey
                .identified_public_key
                .public_key
                .print_key()
        );
        debug!(
            "last_resort_prekey_signature: {}",
            print_slice(&self.signed_last_resort_pqkem_prekey.signature)
        );

        for pk in &self.one_time_curve_prekeys.prekeys {
            debug!(
                "one_time_curve_prekey: {}, {}",
                pk.id,
                pk.public_key.print_key()
            );
        }
        for pk in &self.one_time_pqkem_prekeys.prekeys {
            debug!(
                "one_time_pqkem_prekey: {}, {}, {}",
                pk.identified_public_key.id,
                pk.identified_public_key.public_key.print_key(),
                print_slice(&pk.signature)
            );
        }
    }

    pub fn from_private_bundle<T: EllipticCurveAlgorithm, R: RngCore + CryptoRng>(
        private_bundle: &PrivateBundle,
        curve_type: &T,
        rng: &mut R,
    ) -> Result<Self, GeneralError> {
        Ok(RegistrationBundle {
            identity_key: private_bundle.identity_key.public_key.clone(),
            signed_curve_prekey: SignedCurvePrekey {
                identified_public_key: IdentifiedEllipticCurvePublicKey::from_identified_key_pair(
                    &private_bundle.curve_prekey,
                ),
                signature: curve_type
                    .xeddsa_sign(
                        &private_bundle.identity_key.private_key,
                        &private_bundle.curve_prekey.key_pair.public_key.encode_ec(),
                        rng,
                    )
                    .map_err(|e| GeneralError::XedDSA(e))?,
            },
            signed_last_resort_pqkem_prekey: SignedPQKEMPrekey {
                identified_public_key: IdentifiedPQKEMPublicKey::from_identified_key_pair(
                    &private_bundle.last_resort_prekey,
                ),
                signature: curve_type
                    .xeddsa_sign(
                        &private_bundle.identity_key.private_key,
                        &private_bundle
                            .last_resort_prekey
                            .key_pair
                            .public_key
                            .encode_kem(),
                        rng,
                    )
                    .map_err(|e| GeneralError::XedDSA(e))?,
            },
            one_time_curve_prekeys: OneTimeCurvePrekeySet {
                prekeys: private_bundle
                    .one_time_curve_prekeys
                    .iter()
                    .map(|k| IdentifiedEllipticCurvePublicKey::from_identified_key_pair(&k))
                    .collect(),
            },
            one_time_pqkem_prekeys: SignedOneTimePqkemPrekeySet {
                prekeys: private_bundle
                    .one_time_pqkem_prekeys
                    .iter()
                    .map(|k| {
                        let key = IdentifiedPQKEMPublicKey::from_identified_key_pair(&k);
                        let result = curve_type
                            .xeddsa_sign(
                                &private_bundle.identity_key.private_key,
                                &k.key_pair.public_key.encode_kem(),
                                rng,
                            )
                            .map(|value| SignedPQKEMPrekey {
                                identified_public_key: key,
                                signature: value,
                            })
                            .map_err(|e| GeneralError::XedDSA(e));
                        result
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            },
        })
    }

    pub fn to_protobuf(&self) -> PbRegistrationBundle {
        PbRegistrationBundle {
            identity_key: Some(PbEllipticCurvePublicKey {
                key_type: self.identity_key.key_type.to_protobuf().into(),
                key_bytes: self.identity_key.bytes.clone(),
            }),
            signed_curve_prekey: Some(PbSignedCurvePrekey {
                identified_public_key: Some(PbIdentifiedEllipticCurvePublicKey {
                    uuid: self
                        .signed_curve_prekey
                        .identified_public_key
                        .id
                        .as_bytes()
                        .to_vec(),
                    public_key: Some(PbEllipticCurvePublicKey {
                        key_type: self
                            .signed_curve_prekey
                            .identified_public_key
                            .public_key
                            .key_type
                            .to_protobuf()
                            .into(),
                        key_bytes: self
                            .signed_curve_prekey
                            .identified_public_key
                            .public_key
                            .bytes
                            .clone(),
                    }),
                }),
                signature: self.signed_curve_prekey.signature.to_vec(),
            }),
            signed_last_resort_pqkem_prekey: Some(PbSignedPqkemPrekey {
                identified_public_key: Some(PbIdentifiedPqkemPublicKey {
                    uuid: self
                        .signed_last_resort_pqkem_prekey
                        .identified_public_key
                        .id
                        .as_bytes()
                        .to_vec(),
                    public_key: Some(PbpqkemPublicKey {
                        key_type: self
                            .signed_last_resort_pqkem_prekey
                            .identified_public_key
                            .public_key
                            .key_type
                            .to_protobuf()
                            .into(),
                        key_bytes: self
                            .signed_last_resort_pqkem_prekey
                            .identified_public_key
                            .public_key
                            .bytes
                            .clone(),
                    }),
                }),
                signature: self.signed_last_resort_pqkem_prekey.signature.to_vec(),
            }),
            one_time_curve_prekey_set: Some(PbOneTimeCurvePrekeySet {
                prekeys: self
                    .one_time_curve_prekeys
                    .prekeys
                    .iter()
                    .map(|key| PbIdentifiedEllipticCurvePublicKey {
                        uuid: key.id.as_bytes().to_vec(),
                        public_key: Some(PbEllipticCurvePublicKey {
                            key_type: key.public_key.key_type.to_protobuf().into(),
                            key_bytes: key.public_key.bytes.clone(),
                        }),
                    })
                    .collect(),
            }),
            signed_one_time_pqkem_prekey_set: Some(PbSignedOneTimePqkemPrekeySet {
                prekeys: self
                    .one_time_pqkem_prekeys
                    .prekeys
                    .iter()
                    .map(|key| PbSignedPqkemPrekey {
                        identified_public_key: Some(PbIdentifiedPqkemPublicKey {
                            uuid: key.identified_public_key.id.as_bytes().to_vec(),
                            public_key: Some(PbpqkemPublicKey {
                                key_type: key
                                    .identified_public_key
                                    .public_key
                                    .key_type
                                    .to_protobuf()
                                    .into(),
                                key_bytes: key.identified_public_key.public_key.bytes.clone(),
                            }),
                        }),
                        signature: key.signature.to_vec(),
                    })
                    .collect(),
            }),
        }
    }

    pub fn from_protobuf(
        pb_registration_bundle: PbRegistrationBundle,
    ) -> Result<Self, ProtobufError> {
        // Identity Key
        let pb_identity_key = pb_registration_bundle
            .identity_key
            .ok_or(ProtobufError::MissingField("identity_key"))?;
        let identity_key_type = EllipticCurveType::from_id(pb_identity_key.key_type as u8)
            .ok_or(ProtobufError::InvalidField("identity_key.key_type"))?;
        let identity_key_bytes = pb_identity_key.key_bytes;
        if identity_key_bytes.len() != identity_key_type.public_key_length() {
            return Err(ProtobufError::InvalidField("identity_key.key_bytes"));
        }

        // Signed Curve Prekey
        let pb_signed_curve_prekey = pb_registration_bundle
            .signed_curve_prekey
            .ok_or(ProtobufError::MissingField("signed_curve_prekey"))?;
        let signed_curve_prekey = SignedCurvePrekey::from_protobuf(&pb_signed_curve_prekey)?;

        // Signed Last Resort PQKEM Prekey
        let pb_signed_last_resort_pqkem_prekey = pb_registration_bundle
            .signed_last_resort_pqkem_prekey
            .ok_or(ProtobufError::MissingField(
                "signed_last_resort_pqkem_prekey",
            ))?;
        let signed_last_resort_pqkem_prekey =
            SignedPQKEMPrekey::from_protobuf(&pb_signed_last_resort_pqkem_prekey)?;

        // One-Time Curve Prekeys
        let pb_one_time_curve_prekey_set = pb_registration_bundle
            .one_time_curve_prekey_set
            .ok_or(ProtobufError::MissingField("one_time_curve_prekey_set"))?;
        let one_time_curve_prekeys =
            OneTimeCurvePrekeySet::from_protobuf(&pb_one_time_curve_prekey_set)?;

        // One-Time PQKEM Prekeys
        let pb_one_time_pqkem_prekey_set = pb_registration_bundle
            .signed_one_time_pqkem_prekey_set
            .ok_or(ProtobufError::MissingField(
                "signed_one_time_pqkem_prekey_set",
            ))?;
        let one_time_pqkem_prekeys =
            SignedOneTimePqkemPrekeySet::from_protobuf(&pb_one_time_pqkem_prekey_set)?;

        Ok(Self {
            identity_key: EllipticCurvePublicKey {
                key_type: identity_key_type,
                bytes: identity_key_bytes,
            },
            signed_curve_prekey,
            signed_last_resort_pqkem_prekey,
            one_time_curve_prekeys,
            one_time_pqkem_prekeys,
        })
    }
}
