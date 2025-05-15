pub enum HashType {
    SHA256,
    SHA512,
}

impl HashType {
    pub fn get_output_size(&self) -> usize {
        match self {
            Self::SHA256 => 32,
            Self::SHA512 => 64,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            Self::SHA256 => "SHA-256",
            Self::SHA512 => "SHA-512",
        }
    }
}
