use super::errors::StorageInterfaceError;

pub trait StorageInterface {
    // Creates an instance of the storage
    fn new(application_name: &str, root_path: &str) -> Result<Self, StorageInterfaceError>
    where
        Self: Sized;
}
