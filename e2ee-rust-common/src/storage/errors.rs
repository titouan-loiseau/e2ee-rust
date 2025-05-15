use crate::errors::{encoding::EncodingError, general::ToGeneralError};

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

// Implement ToGeneralError for StorageInterfaceError
impl<T> ToGeneralError<T> for Result<T, StorageInterfaceError> {
    fn to_general_error(self) -> Result<T, crate::errors::general::GeneralError> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(crate::errors::general::GeneralError::StorageError(e)),
        }
    }
}