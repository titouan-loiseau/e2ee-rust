use log::debug;

use crate::{
    crypto::{curve::traits::EllipticCurveAlgorithm, pqkem::traits::PQKEMAlgorithm},
    hash::enum_hash_types::HashType,
    utils::display::print_slice,
};

pub fn kdf<T: EllipticCurveAlgorithm, U: PQKEMAlgorithm>(
    input: &[u8],
    curve_type: &T,
    kyber_type: &U,
    hash_type: &HashType,
    info: &str,
) -> [u8; 32] {
    // Generate the salt
    let hkdf_salt: Vec<u8> = vec![0u8; hash_type.get_output_size()];

    // Generate the IKM
    let mut hkdf_ikm: Vec<u8> = vec![];
    hkdf_ikm.extend_from_slice(curve_type.generate_kdf_ikm_prepad());
    hkdf_ikm.extend_from_slice(input);

    // Generate the info
    let info_string = format!(
        "{}_{}_{}_{}",
        info,
        curve_type.get_type().to_str(),
        hash_type.to_str(),
        kyber_type.get_type().to_str()
    );
    let hkdf_info: &[u8] = info_string.as_bytes();
    debug!("ikm: {}", print_slice(&hkdf_ikm));
    debug!("info: {}", print_slice(&hkdf_info));
    debug!("salt: {}", print_slice(&hkdf_salt));
    debug!("hash_type: {}", hash_type.to_str());
    debug!("curve_type: {}", curve_type.get_type().to_str());
    debug!("kyber_type: {}", kyber_type.get_type().to_str());
    debug!("info: {:?}", info);
    debug!("info_string: {:?}", info_string);

    let mut okm = [0u8; 32];
    let res =
        match hash_type {
            HashType::SHA256 => hkdf::Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt), &hkdf_ikm)
                .expand(hkdf_info, &mut okm),
            HashType::SHA512 => hkdf::Hkdf::<sha2::Sha512>::new(Some(&hkdf_salt), &hkdf_ikm)
                .expand(hkdf_info, &mut okm),
        };
    debug!("OKM: {:?}", okm);
    debug!("res: {:?}", res);

    okm
}
