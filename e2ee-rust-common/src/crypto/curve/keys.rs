use rand::Rng;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::traits::PrintableKey,
    errors::{encoding::EncodingError, protobuf::ProtobufError},
    protobuf::crypto::curve::{PbEllipticCurvePublicKey, PbIdentifiedEllipticCurvePublicKey},
    protobuf::utils::uuid_from_bytes,
};

use super::enum_elliptic_curve_type::EllipticCurveType;

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct EllipticCurvePublicKey {
    pub key_type: EllipticCurveType,
    pub bytes: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct EllipticCurvePrivateKey {
    pub key_type: EllipticCurveType,
    pub bytes: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct EllipticCurveKeyPair {
    pub key_type: EllipticCurveType,
    pub private_key: EllipticCurvePrivateKey,
    pub public_key: EllipticCurvePublicKey,
}

#[derive(Debug, Clone)]
pub struct IdentifiedEllipticCurveKeyPair {
    pub id: Uuid,
    pub key_pair: EllipticCurveKeyPair,
}

#[derive(Debug, Clone)]
pub struct IdentifiedEllipticCurvePublicKey {
    pub id: Uuid,
    pub public_key: EllipticCurvePublicKey,
}

impl EllipticCurveKeyPair {
    pub fn from_bytes(
        key_type: u8,
        public_key_bytes: Vec<u8>,
        private_key_bytes: Vec<u8>,
    ) -> Result<Self, EncodingError> {
        let key_type_enum =
            EllipticCurveType::from_id(key_type).ok_or(EncodingError::InvalidKeyType)?;
        if public_key_bytes.len() != key_type_enum.public_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }
        if private_key_bytes.len() != key_type_enum.private_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }
        Ok(Self {
            key_type: key_type_enum.clone(),
            private_key: EllipticCurvePrivateKey {
                key_type: key_type_enum.clone(),
                bytes: private_key_bytes,
            },
            public_key: EllipticCurvePublicKey {
                key_type: key_type_enum,
                bytes: public_key_bytes,
            },
        })
    }
}

impl EllipticCurvePublicKey {
    pub fn from_bytes(key_type: u8, bytes: Vec<u8>) -> Result<Self, EncodingError> {
        let key_type_enum =
            EllipticCurveType::from_id(key_type).ok_or(EncodingError::InvalidKeyType)?;
        if bytes.len() != key_type_enum.public_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }
        Ok(Self {
            key_type: key_type_enum,
            bytes,
        })
    }

    pub fn from_protobuf(
        pb_elliptic_curve_public_key: &PbEllipticCurvePublicKey,
    ) -> Result<Self, ProtobufError> {
        let elliptic_curve_type =
            EllipticCurveType::from_id(pb_elliptic_curve_public_key.key_type as u8).ok_or(
                ProtobufError::InvalidField("elliptic_curve_public_key.public_key.key_type"),
            )?;

        let public_key_bytes = pb_elliptic_curve_public_key.key_bytes.clone();
        if public_key_bytes.len() != elliptic_curve_type.public_key_length() {
            return Err(ProtobufError::InvalidFieldLength(
                "elliptic_curve_public_key.public_key.key_bytes",
                public_key_bytes.len(),
                elliptic_curve_type.public_key_length(),
            ));
        }

        Ok(Self {
            key_type: elliptic_curve_type,
            bytes: public_key_bytes,
        })
    }
}

impl IdentifiedEllipticCurveKeyPair {
    pub fn generate_from_keypair<R: rand::RngCore + rand::CryptoRng>(
        key_pair: EllipticCurveKeyPair,
        rng: &mut R,
    ) -> Self {
        let uuid_bytes: [u8; 16] = rng.gen();
        Self {
            id: Uuid::from_bytes(uuid_bytes),
            key_pair,
        }
    }
}

impl IdentifiedEllipticCurvePublicKey {
    pub fn from_identified_key_pair(identified_key_pair: &IdentifiedEllipticCurveKeyPair) -> Self {
        Self {
            id: identified_key_pair.id,
            public_key: identified_key_pair.key_pair.public_key.clone(),
        }
    }

    pub fn from_protobuf(
        pb_identified_elliptic_curve_public_key: &PbIdentifiedEllipticCurvePublicKey,
    ) -> Result<Self, ProtobufError> {
        let id = uuid_from_bytes(&pb_identified_elliptic_curve_public_key.uuid)?;
        Ok(IdentifiedEllipticCurvePublicKey {
            id,
            public_key: EllipticCurvePublicKey::from_protobuf(
                pb_identified_elliptic_curve_public_key
                    .public_key
                    .as_ref()
                    .ok_or(ProtobufError::InvalidField(
                        "identified_elliptic_curve_public_key.public_key",
                    ))?,
            )?,
        })
    }

    pub fn to_protobuf(&self) -> PbIdentifiedEllipticCurvePublicKey {
        PbIdentifiedEllipticCurvePublicKey {
            uuid: self.id.as_bytes().to_vec(),
            public_key: Some(self.public_key.to_protobuf()),
        }
    }
}

impl EllipticCurvePublicKey {
    pub fn print_key(&self) -> String {
        format!(
            "0x{}",
            self.bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }

    pub fn encode_ec(&self) -> Vec<u8> {
        let mut encoded = vec![self.key_type.id()];
        encoded.extend_from_slice(&self.bytes);
        encoded
    }

    #[allow(dead_code)]
    pub fn decode_ec(encoded: &[u8]) -> Result<Self, EncodingError> {
        // Check if the encoded data is at least 2 bytes long
        if encoded.len() < 2 {
            return Err(EncodingError::InvalidKeyLength);
        }

        // Extract the key type from the first byte
        let key_type =
            EllipticCurveType::from_id(encoded[0]).ok_or(EncodingError::InvalidKeyType)?;

        // Extract the key bytes from the remaining bytes
        let bytes = encoded[1..].to_vec();

        // Check the length of the key bytes
        if bytes.len() != key_type.public_key_length() {
            return Err(EncodingError::InvalidKeyLength);
        }

        Ok(EllipticCurvePublicKey { key_type, bytes })
    }

    pub fn to_protobuf(&self) -> PbEllipticCurvePublicKey {
        PbEllipticCurvePublicKey {
            key_bytes: self.bytes.clone(),
            key_type: self.key_type.to_protobuf().into(),
        }
    }
}

impl PrintableKey for EllipticCurvePrivateKey {
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

impl PrintableKey for EllipticCurvePublicKey {
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
