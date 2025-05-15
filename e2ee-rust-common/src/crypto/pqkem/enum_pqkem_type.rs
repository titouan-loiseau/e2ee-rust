use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::protobuf::crypto::pqkem::PbpqkemType;

#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Debug, Clone)]
pub enum PQKEMType {
    KYBER512,
    KYBER768,
    KYBER1024,
}

impl PQKEMType {
    pub fn id(&self) -> u8 {
        match self {
            PQKEMType::KYBER512 => 0,
            PQKEMType::KYBER768 => 1,
            PQKEMType::KYBER1024 => 2,
        }
    }

    pub fn from_id(id: u8) -> Option<PQKEMType> {
        match id {
            0 => Some(PQKEMType::KYBER512),
            1 => Some(PQKEMType::KYBER768),
            2 => Some(PQKEMType::KYBER1024),
            _ => None,
        }
    }

    pub fn public_key_length(&self) -> usize {
        match self {
            PQKEMType::KYBER512 => 800,
            PQKEMType::KYBER768 => 1184,
            PQKEMType::KYBER1024 => 1568,
        }
    }

    pub fn private_key_length(&self) -> usize {
        match self {
            PQKEMType::KYBER512 => 1632,
            PQKEMType::KYBER768 => 2400,
            PQKEMType::KYBER1024 => 3168,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            PQKEMType::KYBER512 => "CRYSTALS-KYBER-512",
            PQKEMType::KYBER768 => "CRYSTALS-KYBER-768",
            PQKEMType::KYBER1024 => "CRYSTALS-KYBER-1024",
        }
    }

    pub fn to_protobuf(&self) -> PbpqkemType {
        match self {
            PQKEMType::KYBER512 => PbpqkemType::Kyber512,
            PQKEMType::KYBER768 => PbpqkemType::Kyber768,
            PQKEMType::KYBER1024 => PbpqkemType::Kyber1024,
        }
    }
}
