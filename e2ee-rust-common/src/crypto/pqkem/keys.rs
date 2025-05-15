use rand::Rng;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::traits::PrintableKey,
    errors::encoding::EncodingError,
    protobuf::crypto::pqkem::{PbIdentifiedPqkemPublicKey, PbpqkemPublicKey},
};

use super::enum_pqkem_type::PQKEMType;

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct PQKEMPublicKey {
    pub key_type: PQKEMType,
    pub bytes: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct PQKEMPrivateKey {
    pub key_type: PQKEMType,
    pub bytes: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct PQKEMKeyPair {
    pub key_type: PQKEMType,
    pub private_key: PQKEMPrivateKey,
    pub public_key: PQKEMPublicKey,
}

#[derive(Debug, Clone)]
pub struct IdentifiedPQKEMKeyPair {
    pub id: Uuid,
    pub key_pair: PQKEMKeyPair,
}

#[derive(Debug, Clone)]
pub struct IdentifiedPQKEMPublicKey {
    pub id: Uuid,
    pub public_key: PQKEMPublicKey,
}

impl PQKEMPublicKey {
    pub fn from_bytes(key_type: u8, bytes: Vec<u8>) -> Result<Self, EncodingError> {
        let key_type = PQKEMType::from_id(key_type).ok_or(EncodingError::InvalidKeyType)?;

        if bytes.len() != key_type.public_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }

        Ok(Self { key_type, bytes })
    }
}

impl PQKEMKeyPair {
    pub fn from_bytes(
        key_type: u8,
        public_key_bytes: Vec<u8>,
        private_key_bytes: Vec<u8>,
    ) -> Result<Self, EncodingError> {
        let key_type = PQKEMType::from_id(key_type).ok_or(EncodingError::InvalidKeyType)?;
        let public_key = PQKEMPublicKey::from_bytes(key_type.id(), public_key_bytes)?;

        if private_key_bytes.len() != key_type.private_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }
        let private_key = PQKEMPrivateKey {
            bytes: private_key_bytes,
            key_type: key_type.clone(),
        };
        Ok(Self {
            key_type,
            public_key,
            private_key,
        })
    }
}

impl IdentifiedPQKEMKeyPair {
    pub fn generate_from_key_pair<R: rand::RngCore + rand::CryptoRng>(
        key_pair: &PQKEMKeyPair,
        rng: &mut R,
    ) -> Self {
        let uuid_bytes: [u8; 16] = rng.gen();
        Self {
            id: Uuid::from_bytes(uuid_bytes),
            key_pair: key_pair.clone(),
        }
    }
}

impl IdentifiedPQKEMPublicKey {
    pub fn from_identified_key_pair(identified_key_pair: &IdentifiedPQKEMKeyPair) -> Self {
        Self {
            id: identified_key_pair.id,
            public_key: identified_key_pair.key_pair.public_key.clone(),
        }
    }

    pub fn to_protobuf(&self) -> PbIdentifiedPqkemPublicKey {
        PbIdentifiedPqkemPublicKey {
            uuid: self.id.as_bytes().to_vec(),
            public_key: Some(self.public_key.to_protobuf()),
        }
    }
}

impl PQKEMPublicKey {
    pub fn print_key(&self) -> String {
        format!(
            "0x{}",
            self.bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }

    pub fn encode_kem(&self) -> Vec<u8> {
        let mut encoded = vec![self.key_type.id()];
        encoded.extend_from_slice(&self.bytes);
        encoded
    }

    #[allow(dead_code)]
    pub fn decode_kem(encoded: &[u8]) -> Result<Self, EncodingError> {
        // Check if the encoded data is at least 2 bytes long
        if encoded.len() < 2 {
            return Err(EncodingError::InvalidKeyLength);
        }

        // Extract the key type from the first byte
        let key_type = PQKEMType::from_id(encoded[0]).ok_or(EncodingError::InvalidKeyType)?;

        // Extract the key bytes from the remaining bytes
        let bytes = encoded[1..].to_vec();

        // Check the length of the key bytes
        if bytes.len() != key_type.public_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }

        Ok(PQKEMPublicKey { key_type, bytes })
    }

    pub fn to_protobuf(&self) -> PbpqkemPublicKey {
        PbpqkemPublicKey {
            key_type: self.key_type.to_protobuf().into(),
            key_bytes: self.bytes.as_slice().to_vec(),
        }
    }
}

impl PrintableKey for PQKEMPrivateKey {
    fn print_key(&self) -> String {
        format!(
            "0x{}",
            self.bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

impl PrintableKey for PQKEMPublicKey {
    fn print_key(&self) -> String {
        format!(
            "0x{}",
            self.bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}
