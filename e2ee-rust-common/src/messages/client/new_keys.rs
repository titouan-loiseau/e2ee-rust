use crate::{
    errors::protobuf::ProtobufError,
    pqxdh::{
        one_time_curve_prekey_set::OneTimeCurvePrekeySet, signed_curve_prekey::SignedCurvePrekey,
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    protobuf::client::{pb_new_keys, PbNewKeys},
};

pub struct NewKeys {
    pub keys_type: NewKeysType,
    pub signed_curve_prekey: Option<SignedCurvePrekey>,
    pub signed_last_resort_pqkem_prekey: Option<SignedPQKEMPrekey>,
    pub one_time_curve_prekey_set: Option<OneTimeCurvePrekeySet>,
    pub signed_one_time_pqkem_prekey_set: Option<SignedOneTimePqkemPrekeySet>,
}

pub enum NewKeysType {
    SignedCurvePrekey,
    SignedLastResortPQKEMPrekey,
    OneTimeCurvePrekeySet,
    SignedOneTimePQKEMPrekeySet,
}

impl NewKeys {
    pub fn to_protobuf(&self) -> PbNewKeys {
        PbNewKeys {
            new_keys: match self.keys_type {
                NewKeysType::SignedCurvePrekey => Some(pb_new_keys::NewKeys::SignedCurvePrekey(
                    self.signed_curve_prekey.as_ref().unwrap().to_protobuf(),
                )),
                NewKeysType::SignedLastResortPQKEMPrekey => {
                    Some(pb_new_keys::NewKeys::SignedLastResortPqkemPrekey(
                        self.signed_last_resort_pqkem_prekey
                            .as_ref()
                            .unwrap()
                            .to_protobuf(),
                    ))
                }
                NewKeysType::OneTimeCurvePrekeySet => {
                    Some(pb_new_keys::NewKeys::OneTimeCurvePrekeys(
                        self.one_time_curve_prekey_set
                            .as_ref()
                            .unwrap()
                            .to_protobuf(),
                    ))
                }
                NewKeysType::SignedOneTimePQKEMPrekeySet => {
                    Some(pb_new_keys::NewKeys::SignedOneTimePqkemPrekeys(
                        self.signed_one_time_pqkem_prekey_set
                            .as_ref()
                            .unwrap()
                            .to_protobuf(),
                    ))
                }
            },
        }
    }

    pub fn from_protobuf(pb_new_keys: &PbNewKeys) -> Result<Self, ProtobufError> {
        let new_keys = pb_new_keys
            .new_keys
            .as_ref()
            .ok_or(ProtobufError::MissingField("new_keys"))?;

        match new_keys {
            pb_new_keys::NewKeys::SignedCurvePrekey(pb_signed_curve_prekey) => Ok(Self {
                keys_type: NewKeysType::SignedCurvePrekey,
                signed_curve_prekey: Some(SignedCurvePrekey::from_protobuf(
                    pb_signed_curve_prekey,
                )?),
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: None,
            }),
            pb_new_keys::NewKeys::SignedLastResortPqkemPrekey(pb_signed_pqkem_prekey) => Ok(Self {
                keys_type: NewKeysType::SignedLastResortPQKEMPrekey,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: Some(SignedPQKEMPrekey::from_protobuf(
                    pb_signed_pqkem_prekey,
                )?),
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: None,
            }),
            pb_new_keys::NewKeys::OneTimeCurvePrekeys(pb_one_time_curve_prekey_set) => Ok(Self {
                keys_type: NewKeysType::OneTimeCurvePrekeySet,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: Some(OneTimeCurvePrekeySet::from_protobuf(
                    pb_one_time_curve_prekey_set,
                )?),
                signed_one_time_pqkem_prekey_set: None,
            }),
            pb_new_keys::NewKeys::SignedOneTimePqkemPrekeys(
                pb_signed_one_time_pqkem_prekey_set,
            ) => Ok(Self {
                keys_type: NewKeysType::SignedOneTimePQKEMPrekeySet,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: Some(SignedOneTimePqkemPrekeySet::from_protobuf(
                    pb_signed_one_time_pqkem_prekey_set,
                )?),
            }),
        }
    }
}
