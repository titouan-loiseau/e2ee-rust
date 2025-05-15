use chrono::{DateTime, Utc};
use e2ee_rust_common::storage::errors::StorageInterfaceError;
use rusqlite::Connection;

use crate::ToStorageInterfaceError;

pub fn timestamp_to_datetime(timestamp: i64) -> Result<DateTime<Utc>, StorageInterfaceError> {
    DateTime::from_timestamp_millis(timestamp).ok_or(StorageInterfaceError::BadTimestamp)
}

pub fn datetime_to_timestamp(datetime: &DateTime<Utc>) -> i64 {
    datetime.timestamp_millis()
}

pub fn uuid_from_bytes(bytes: &[u8]) -> Result<uuid::Uuid, StorageInterfaceError> {
    uuid::Uuid::from_slice(bytes).map_err(|_| StorageInterfaceError::BadUuid)
}

// Insert a row and return the id of the inserted row
pub fn insert_returning_id(
    statement_str: &str,
    params: &[&dyn rusqlite::types::ToSql],
    tablename: &str,
    connection: &Connection,
) -> Result<i32, StorageInterfaceError> {
    // Prepare the statement
    let mut statement = connection
        .prepare(statement_str)
        .to_storage_interface_error()?;

    // Execute the insert
    let mut res = statement.query(params).to_storage_interface_error()?;

    // Get the returning row
    if let Some(row) = res.next().to_storage_interface_error()? {
        let id: i32 = row.get(0).to_storage_interface_error()?;
        return Ok(id);
    }

    // Return an error if the insert failed
    Err(StorageInterfaceError::CustomError(format!(
        "Failed to insert into {}",
        tablename
    )))
}

// Performs an update and returns the amount of rows modified
pub fn perform_update(
    statement_str: &str,
    params: &[&dyn rusqlite::types::ToSql],
    connection: &Connection,
) -> Result<usize, StorageInterfaceError> {
    // Prepare the statement
    let mut statement = connection
        .prepare(statement_str)
        .to_storage_interface_error()?;

    // Execute the insert
    let res = statement.execute(params).to_storage_interface_error()?;

    Ok(res)
}
