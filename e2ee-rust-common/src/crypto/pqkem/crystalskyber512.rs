use pqc_kyber::{decapsulate, encapsulate, Keypair};

use crate::errors::pqkem::PQKEMError;

use super::{
    enum_pqkem_type::PQKEMType,
    keys::{IdentifiedPQKEMKeyPair, PQKEMKeyPair, PQKEMPrivateKey, PQKEMPublicKey},
    traits::PQKEMAlgorithm,
};
pub struct CrystalsKyber512 {}

impl PQKEMAlgorithm for CrystalsKyber512 {
    fn generate_key_pair<R: rand::RngCore + rand::CryptoRng>(&self, rng: &mut R) -> PQKEMKeyPair {
        let keypair = Keypair::generate(rng).unwrap();

        PQKEMKeyPair {
            key_type: PQKEMType::KYBER512,
            private_key: PQKEMPrivateKey {
                key_type: PQKEMType::KYBER512,
                bytes: keypair.secret.to_vec(),
            },
            public_key: PQKEMPublicKey {
                key_type: PQKEMType::KYBER512,
                bytes: keypair.public.to_vec(),
            },
        }
    }

    fn generate_identified_key_pair<R: rand::RngCore + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> IdentifiedPQKEMKeyPair {
        IdentifiedPQKEMKeyPair::generate_from_key_pair(&self.generate_key_pair(rng), rng)
    }

    fn encapsulate<R: rand::RngCore + rand::CryptoRng>(
        &self,
        public_key: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>), PQKEMError> {
        let (ct, ss) = encapsulate(public_key, rng).map_err(|_| PQKEMError::EncapsulationError)?;
        Ok((ct.to_vec(), ss.to_vec()))
    }

    fn decapsulate(&self, private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PQKEMError> {
        Ok(decapsulate(ciphertext, private_key)
            .map_err(|_| PQKEMError::DecapsulationError)?
            .to_vec())
    }

    fn get_type(&self) -> PQKEMType {
        PQKEMType::KYBER512
    }
}
