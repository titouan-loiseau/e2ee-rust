use crate::errors::pqkem::PQKEMError;

use super::{
    enum_pqkem_type::PQKEMType,
    keys::{IdentifiedPQKEMKeyPair, PQKEMKeyPair},
};

pub trait PQKEMAlgorithm {
    // Generate a key pair for the PQKEM algorithm
    fn generate_key_pair<R: rand::RngCore + rand::CryptoRng>(&self, rng: &mut R) -> PQKEMKeyPair;

    // Generate an identified key pair for the PQKEM algorithm
    fn generate_identified_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> IdentifiedPQKEMKeyPair;

    // Perform key encapsulation for the PQKEM algorithm
    // Returns a tuple of (ciphertext, shared_secret)
    fn encapsulate<R: rand::RngCore + rand::CryptoRng>(
        &self,
        public_key: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>), PQKEMError>;

    // Perform key decapsulation for the PQKEM algorithm
    fn decapsulate(&self, private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PQKEMError>;

    // Get the type of the PQKEM algorithm
    fn get_type(&self) -> PQKEMType;
}
