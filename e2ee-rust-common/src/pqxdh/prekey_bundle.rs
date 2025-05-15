use log::debug;

use crate::{
    crypto::curve::keys::{EllipticCurvePublicKey, IdentifiedEllipticCurvePublicKey},
    utils::display::print_slice,
};

use super::{
    registration_bundle::RegistrationBundle, signed_curve_prekey::SignedCurvePrekey,
    signed_pqkem_prekey::SignedPQKEMPrekey,
};

pub struct PrekeyBundle {
    pub identity_key: EllipticCurvePublicKey,
    pub signed_curve_prekey: SignedCurvePrekey,
    pub one_time_pqkem_prekey: SignedPQKEMPrekey,
    pub one_time_curve_prekey: Option<IdentifiedEllipticCurvePublicKey>,
}

impl PrekeyBundle {
    pub fn from_registration_bundle(registration_bundle: &mut RegistrationBundle) -> Self {
        // Use one of the one-time prekeys if available
        let used_one_time_curve_prekey = registration_bundle.one_time_curve_prekeys.prekeys.pop();

        // Use one of the one-time prekeys, and if not available, use the last resort prekey
        let used_one_time_pqkem_prekey = registration_bundle
            .one_time_pqkem_prekeys
            .prekeys
            .pop()
            .unwrap_or(registration_bundle.signed_last_resort_pqkem_prekey.clone());

        Self {
            identity_key: registration_bundle.identity_key.clone(),
            signed_curve_prekey: registration_bundle.signed_curve_prekey.clone(),
            one_time_pqkem_prekey: used_one_time_pqkem_prekey,
            one_time_curve_prekey: used_one_time_curve_prekey,
        }
    }

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
            "one_time_pqkem_prekey: {}, {}",
            self.one_time_pqkem_prekey.identified_public_key.id,
            self.one_time_pqkem_prekey
                .identified_public_key
                .public_key
                .print_key()
        );
        debug!(
            "one_time_pqkem_prekey_signature: {}",
            print_slice(&self.one_time_pqkem_prekey.signature)
        );
        if let Some(c_pk) = &self.one_time_curve_prekey {
            debug!(
                "one_time_curve_prekey: {}, {}",
                c_pk.id,
                c_pk.public_key.print_key()
            );
        } else {
            debug!("one_time_curve_prekey: None");
        }
    }
}
