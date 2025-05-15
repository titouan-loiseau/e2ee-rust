use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::aead::AEADError;

use super::enum_aead_types::AEADType;

pub trait AEADScheme<KeyT: AsRef<[u8]>, NonceT: AsRef<[u8]>>: Zeroize + ZeroizeOnDrop {
    // Encrypts the plaintext using the key and associated data, returning the ciphertext and the nonce used
    fn encrypt<R: rand::RngCore + rand::CryptoRng>(
        &self,
        key: &KeyT,
        plaintext: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, NonceT), AEADError>;

    // Decrypts the ciphertext using the key and associated data, returning the plaintext
    fn decrypt(
        &self,
        key: &KeyT,
        ciphertext: &[u8],
        associated_data: &[u8],
        nonce: &NonceT,
    ) -> Result<Vec<u8>, AEADError>;

    // Get the type of the AEAD scheme
    fn get_type(&self) -> AEADType;
}
