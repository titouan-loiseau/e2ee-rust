mod client;
mod server;
mod utils;

use e2ee_rust_common::storage::{
    errors::{InitializationError, StorageInterfaceError},
    storage_interface::StorageInterface,
};
use rusqlite::Connection;
use server::consts::REQ_FIND_TABLES;

const SERVER_SCHEMA_VERSION: i32 = 1;
const CLIENT_SCHEMA_VERSION: i32 = 1;

pub struct SQLiteStorage {
    connection: Connection,
}

impl SQLiteStorage {
    fn init(
        &self,
        schema: &'static str,
        expected_version: i32,
    ) -> Result<(), StorageInterfaceError> {
        // Check if the database exists
        let table_exists = self
            .connection
            .query_row(REQ_FIND_TABLES, [], |row| row.get::<_, String>(0))
            .is_ok();

        if !table_exists {
            // Create the database schema from the schema_server.sql file
            self.connection.execute_batch(schema).map_err(|_| {
                StorageInterfaceError::InitializationError(InitializationError::CannotCreateSchema)
            })?;
        } else {
            // Check the database schema version using PRAGMA schema.schema_version;
            let schema_version = self
                .connection
                .query_row("PRAGMA user_version;", [], |row| row.get::<_, i32>(0))
                .map_err(|_| {
                    StorageInterfaceError::InitializationError(InitializationError::NoSchemaVersion)
                })?;
            if schema_version != expected_version {
                return Err(StorageInterfaceError::InitializationError(
                    InitializationError::IncompatibleSchemaVersion(
                        schema_version,
                        SERVER_SCHEMA_VERSION,
                    ),
                ));
            }
        }

        // Return Ok if the database schema is initialized successfully
        Ok(())
    }
}

impl StorageInterface for SQLiteStorage {
    fn new(application_name: &str, root_path: &str) -> Result<Self, StorageInterfaceError> {
        let db_path = format!("{}/db_{}.sqlite", root_path, application_name);
        let connection = Connection::open(db_path).map_err(|_| {
            StorageInterfaceError::InitializationError(InitializationError::CannotCreateConnection)
        })?;

        // Create the SQLiteStorage instance and initialize the database schema
        let storage = SQLiteStorage { connection };

        // Return the initialized SQLiteStorage instance
        Ok(storage)
    }
}

// Error convertion from rusqlite::Error to StorageInterfaceError
pub trait ToStorageInterfaceError<T> {
    fn to_storage_interface_error(self) -> Result<T, StorageInterfaceError>;
}

impl<T> ToStorageInterfaceError<T> for Result<T, rusqlite::Error> {
    fn to_storage_interface_error(self) -> Result<T, StorageInterfaceError> {
        self.map_err(|e| StorageInterfaceError::CustomError(format!("SQLite error: {}", e)))
    }
}
