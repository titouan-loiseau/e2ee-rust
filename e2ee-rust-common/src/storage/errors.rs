use crate::errors::encoding::EncodingError;

use super::{client::errors::ClientStorageError, server::errors::ServerStorageError};

#[derive(Debug, Clone)]
pub enum StorageInterfaceError {
    BadApplicationName,
    BadRootPath,
    InitializationError(InitializationError),
    CloseError,
    BadKeyType,
    BadKeySize,
    BadTimestamp,
    BadUuid,
    BadSignature,
    CustomError(String),
    ServerStorageError(ServerStorageError),
    ClientStorageError(ClientStorageError),
}

#[derive(Debug, Clone)]
pub enum InitializationError {
    CannotCreateSchema,
    NoSchemaVersion,
    IncompatibleSchemaVersion(i32, i32),
    CannotCreateConnection,
}

impl From<EncodingError> for StorageInterfaceError {
    fn from(error: EncodingError) -> Self {
        match error {
            EncodingError::InvalidKeyLength => StorageInterfaceError::BadKeySize,
            EncodingError::InvalidKeyType => StorageInterfaceError::BadKeyType,
        }
    }
}
