use log::debug;
use uuid::Uuid;

use crate::{
    crypto::{aead::enum_aead_types::AEADType, curve::keys::EllipticCurvePublicKey},
    utils::display::print_slice,
};

pub struct FirstMessage {
    pub peer_identity_key: EllipticCurvePublicKey,
    pub peer_ephemeral_key: EllipticCurvePublicKey,
    pub pqkem_ciphertext: Vec<u8>,
    pub used_curve_prekey_id: Option<Uuid>,
    pub used_pqkem_prekey_id: Uuid,
    pub ciphertext: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub encryption_type: AEADType,
}

impl FirstMessage {
    pub fn print(&self) {
        debug!("peer_identity_key: {}", self.peer_identity_key.print_key());
        debug!(
            "peer_ephemeral_key: {}",
            self.peer_ephemeral_key.print_key()
        );
        debug!("pqkem_ciphertext: {}", print_slice(&self.pqkem_ciphertext));
        debug!("used_curve_prekey_id: {:?}", self.used_curve_prekey_id);
        debug!("used_pqkem_prekey_id: {:?}", self.used_pqkem_prekey_id);
        debug!("ciphertext: {}", print_slice(&self.ciphertext));
    }
}
