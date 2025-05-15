use rand::{CryptoRng, RngCore};
use xeddsa::{Sign, Verify};

use crate::errors::{diffie_hellman::DiffieHellmanError, xeddsa::XedDSAError};

use super::{
    enum_elliptic_curve_type::EllipticCurveType,
    keys::{
        EllipticCurveKeyPair, EllipticCurvePrivateKey, EllipticCurvePublicKey,
        IdentifiedEllipticCurveKeyPair,
    },
    traits::EllipticCurveAlgorithm,
};

pub struct Curve25519 {}

impl EllipticCurveAlgorithm for Curve25519 {
    fn generate_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> EllipticCurveKeyPair {
        let private_key = x25519_dalek::StaticSecret::random_from_rng(rng);
        let public_key = x25519_dalek::PublicKey::from(&private_key);

        EllipticCurveKeyPair {
            key_type: EllipticCurveType::CURVE25519,
            private_key: EllipticCurvePrivateKey {
                key_type: EllipticCurveType::CURVE25519,
                bytes: private_key.to_bytes().to_vec(),
            },
            public_key: EllipticCurvePublicKey {
                key_type: EllipticCurveType::CURVE25519,
                bytes: public_key.as_bytes().to_vec(),
            },
        }
    }

    fn generate_identified_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> IdentifiedEllipticCurveKeyPair {
        IdentifiedEllipticCurveKeyPair::generate_from_keypair(self.generate_key_pair(rng), rng)
    }

    fn generate_kdf_ikm_prepad(&self) -> &[u8] {
        &[0xff; 32]
    }

    fn get_type(&self) -> EllipticCurveType {
        EllipticCurveType::CURVE25519
    }

    fn dh(
        &self,
        private_key: &EllipticCurvePrivateKey,
        public_key: &EllipticCurvePublicKey,
    ) -> Result<[u8; 32], DiffieHellmanError> {
        if public_key.key_type != EllipticCurveType::CURVE25519
            || private_key.key_type != EllipticCurveType::CURVE25519
        {
            return Err(DiffieHellmanError::WrongKeyType);
        }

        let priv_bytes: [u8; 32] = private_key.bytes.as_slice().try_into().unwrap();
        let pub_bytes: [u8; 32] = public_key.bytes.as_slice().try_into().unwrap();

        Ok(x25519_dalek::x25519(priv_bytes, pub_bytes))
    }

    fn xeddsa_sign<R: RngCore + CryptoRng>(
        &self,
        private_key: &EllipticCurvePrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<[u8; 64], XedDSAError> {
        if private_key.key_type != EllipticCurveType::CURVE25519 {
            return Err(XedDSAError::WrongKeyType);
        }
        let private_key_bytes: [u8; 32] = private_key.bytes.as_slice().try_into().unwrap();

        let key = xeddsa::xed25519::PrivateKey::from(&private_key_bytes);
        let sign: [u8; 64] = key.sign(message, rng);

        Ok(sign)
    }

    fn xeddsa_verify(
        &self,
        public_key: &EllipticCurvePublicKey,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, XedDSAError> {
        if public_key.key_type != EllipticCurveType::CURVE25519 {
            return Err(XedDSAError::WrongKeyType);
        }
        let public_key_bytes: [u8; 32] = public_key.bytes.as_slice().try_into().unwrap();

        let key =
            xeddsa::xed25519::PublicKey::from(&x25519_dalek::PublicKey::from(public_key_bytes));
        match key.verify(message, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
