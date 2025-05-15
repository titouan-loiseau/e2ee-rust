use chrono::{DateTime, Utc};

use crate::{
    crypto::curve::keys::EllipticCurvePublicKey,
    pqxdh::{
        one_time_curve_prekey_set::OneTimeCurvePrekeySet, signed_curve_prekey::SignedCurvePrekey,
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
};

pub struct ClientInformation {
    pub key_bundle: ClientKeyBundle,
}

#[derive(Clone)]
pub struct ClientKeyBundle {
    pub identity_key: (EllipticCurvePublicKey, DateTime<Utc>),
    pub signed_curve_prekey: (SignedCurvePrekey, DateTime<Utc>),
    pub signed_last_resort_pqkem_prekey: (SignedPQKEMPrekey, DateTime<Utc>),
    pub one_time_curve_prekeys: OneTimeCurvePrekeySet,
    pub signed_one_time_pqkem_prekeys: SignedOneTimePqkemPrekeySet,
}
