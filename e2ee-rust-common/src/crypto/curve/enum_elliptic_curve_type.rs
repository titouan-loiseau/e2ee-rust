use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::protobuf::crypto::curve::PbEllipticCurveType;

#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Debug, Clone)]
pub enum EllipticCurveType {
    CURVE25519,
    CURVE448,
}

impl EllipticCurveType {
    pub fn id(&self) -> u8 {
        match self {
            EllipticCurveType::CURVE25519 => 0,
            EllipticCurveType::CURVE448 => 1,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            EllipticCurveType::CURVE25519 => "CURVE-25519",
            EllipticCurveType::CURVE448 => "CURVE-448",
        }
    }

    pub fn from_id(id: u8) -> Option<EllipticCurveType> {
        match id {
            0 => Some(EllipticCurveType::CURVE25519),
            1 => Some(EllipticCurveType::CURVE448),
            _ => None,
        }
    }

    pub fn public_key_length(&self) -> usize {
        match self {
            EllipticCurveType::CURVE25519 => 32,
            EllipticCurveType::CURVE448 => 56,
        }
    }

    pub fn private_key_length(&self) -> usize {
        match self {
            EllipticCurveType::CURVE25519 => 32,
            EllipticCurveType::CURVE448 => 56,
        }
    }

    pub fn to_protobuf(&self) -> PbEllipticCurveType {
        match self {
            EllipticCurveType::CURVE25519 => PbEllipticCurveType::Curve25519,
            EllipticCurveType::CURVE448 => PbEllipticCurveType::Curve448,
        }
    }
}
