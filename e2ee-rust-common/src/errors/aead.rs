#[derive(Debug)]
pub enum AEADError {
    NotEnoughMemory,
    AuthenticationFailed,
    InvalidNonceSize,
}
