use crate::storage::errors::StorageInterfaceError;

use super::{
    aead::AEADError, diffie_hellman::DiffieHellmanError, encoding::EncodingError,
    pqkem::PQKEMError, protobuf::ProtobufError, xeddsa::XedDSAError, zmq::ZMQError,
};

#[derive(Debug)]
pub enum GeneralError {
    EncodingDecoding(EncodingError),
    DiffieHellman(DiffieHellmanError),
    XedDSA(XedDSAError),
    AEAD(AEADError),
    PQKEM(PQKEMError),
    Protobuf(ProtobufError),
    ZMQ(ZMQError),
    ServerError,
    ClientError,
    StorageError(StorageInterfaceError),
}

impl std::fmt::Display for GeneralError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GeneralError::EncodingDecoding(e) => write!(f, "Encoding/decoding error: {:?}", e),
            GeneralError::DiffieHellman(e) => write!(f, "Diffie-Hellman error: {:?}", e),
            GeneralError::XedDSA(e) => write!(f, "XedDSA signature error: {:?}", e),
            GeneralError::AEAD(e) => write!(f, "AEAD error: {:?}", e),
            GeneralError::PQKEM(e) => write!(f, "PQKEM error: {:?}", e),
            GeneralError::Protobuf(e) => write!(f, "Protobuf error: {:?}", e),
            GeneralError::ZMQ(e) => write!(f, "ZMQ error: {:?}", e),
            GeneralError::ServerError => write!(f, "Server error"),
            GeneralError::ClientError => write!(f, "Client error"),
            GeneralError::StorageError(e) => write!(f, "Storage error: {:?}", e),
        }
    }
}

// Error convertion trait to GeneralError
pub trait ToGeneralError<T> {
    fn to_general_error(self) -> Result<T, GeneralError>;
}
