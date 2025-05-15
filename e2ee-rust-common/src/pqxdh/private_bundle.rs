use log::debug;

use crate::crypto::{
    curve::{
        keys::{EllipticCurveKeyPair, IdentifiedEllipticCurveKeyPair},
        traits::EllipticCurveAlgorithm,
    },
    pqkem::{keys::IdentifiedPQKEMKeyPair, traits::PQKEMAlgorithm},
    traits::PrintableKey,
};

pub struct PrivateBundle {
    pub identity_key: EllipticCurveKeyPair,
    pub curve_prekey: IdentifiedEllipticCurveKeyPair,
    pub last_resort_prekey: IdentifiedPQKEMKeyPair,
    pub one_time_curve_prekeys: Vec<IdentifiedEllipticCurveKeyPair>,
    pub one_time_pqkem_prekeys: Vec<IdentifiedPQKEMKeyPair>,
}

impl PrivateBundle {
    pub fn new<T: EllipticCurveAlgorithm, U: PQKEMAlgorithm, R: rand::RngCore + rand::CryptoRng>(
        curve_type: &T,
        pqkem_type: &U,
        nb_ot_curve_prekeys: usize,
        nb_ot_pqkem_prekeys: usize,
        rng: &mut R,
    ) -> Self {
        PrivateBundle {
            identity_key: curve_type.generate_key_pair(rng),
            curve_prekey: curve_type.generate_identified_key_pair(rng),
            last_resort_prekey: pqkem_type.generate_identified_key_pair(rng),
            one_time_curve_prekeys: (0..nb_ot_curve_prekeys)
                .map(|_| curve_type.generate_identified_key_pair(rng))
                .collect(),
            one_time_pqkem_prekeys: (0..nb_ot_pqkem_prekeys)
                .map(|_| pqkem_type.generate_identified_key_pair(rng))
                .collect(),
        }
    }

    pub fn print(&self) {
        debug!(
            "identity_key: {}",
            self.identity_key.private_key.print_key()
        );
        debug!(
            "curve_prekey: {}, {}",
            self.curve_prekey.id,
            self.curve_prekey.key_pair.private_key.print_key()
        );
        debug!(
            "last_resort_prekey: {}, {}",
            self.last_resort_prekey.id,
            self.last_resort_prekey.key_pair.private_key.print_key()
        );
        for c_pk in &self.one_time_curve_prekeys {
            debug!(
                "one_time_curve_prekey: {}, {}",
                c_pk.id,
                c_pk.key_pair.private_key.print_key()
            );
        }
        for pq_pk in &self.one_time_pqkem_prekeys {
            debug!(
                "one_time_pqkem_prekey: {}, {}",
                pq_pk.id,
                pq_pk.key_pair.private_key.print_key()
            );
        }
    }
}
