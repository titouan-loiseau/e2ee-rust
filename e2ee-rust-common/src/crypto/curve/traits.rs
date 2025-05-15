use rand::{CryptoRng, RngCore};

use crate::errors::{diffie_hellman::DiffieHellmanError, xeddsa::XedDSAError};

use super::{
    enum_elliptic_curve_type::EllipticCurveType,
    keys::{
        EllipticCurveKeyPair, EllipticCurvePrivateKey, EllipticCurvePublicKey,
        IdentifiedEllipticCurveKeyPair,
    },
};

pub trait EllipticCurveAlgorithm {
    // Generate a key pair for the elliptic curve algorithm
    fn generate_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> EllipticCurveKeyPair;

    // Generate an identified key pair for the elliptic curve algorithm
    fn generate_identified_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> IdentifiedEllipticCurveKeyPair;

    // Generate the IKM prepad for the KDF (see https://signal.org/docs/specifications/pqxdh/#cryptographic-notation)
    fn generate_kdf_ikm_prepad(&self) -> &[u8];

    // Get the type of the elliptic curve algorithm
    fn get_type(&self) -> EllipticCurveType;

    // Perform the Diffie-Hellman key exchange
    fn dh(
        &self,
        private_key: &EllipticCurvePrivateKey,
        public_key: &EllipticCurvePublicKey,
    ) -> Result<[u8; 32], DiffieHellmanError>;

    // Perform an XEdDSA signature
    fn xeddsa_sign<R: RngCore + CryptoRng>(
        &self,
        private_key: &EllipticCurvePrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<[u8; 64], XedDSAError>;

    // Verify an XEdDSA signature
    fn xeddsa_verify(
        &self,
        public_key: &EllipticCurvePublicKey,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, XedDSAError>;
}
