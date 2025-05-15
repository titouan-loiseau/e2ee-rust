use aes_gcm::{aead::AeadMutInPlace, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::aead::AEADError;

use super::{enum_aead_types::AEADType, traits::AEADScheme};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AES256GCM {}

impl AEADScheme<[u8; 32], [u8; 12]> for AES256GCM {
    fn encrypt<R: rand::RngCore + rand::CryptoRng>(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, [u8; 12]), AEADError> {
        let aead_key = Key::<Aes256Gcm>::from_slice(key);

        let mut cipher = Aes256Gcm::new(&aead_key);
        let nonce = Aes256Gcm::generate_nonce(rng);
        let nonce_bytes: [u8; 12] = nonce.into();

        let mut buffer = plaintext.to_vec();
        cipher
            .encrypt_in_place(&nonce, &associated_data, &mut buffer)
            .map_err(|_| AEADError::NotEnoughMemory)?;

        Ok((buffer, nonce_bytes))
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, AEADError> {
        let mut buffer = ciphertext.to_vec();
        let aead_key = Key::<Aes256Gcm>::from_slice(key);
        let mut cipher = Aes256Gcm::new(&aead_key);

        match cipher.decrypt_in_place(&Nonce::from_slice(nonce), &associated_data, &mut buffer) {
            Ok(()) => Ok(buffer),
            Err(_) => Err(AEADError::AuthenticationFailed),
        }
    }

    fn get_type(&self) -> super::enum_aead_types::AEADType {
        AEADType::AES256GCM
    }
}
