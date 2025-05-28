use std::io::{stdout, Stdout, Write};

use crossterm::{
    cursor::{Hide, MoveTo},
    terminal::{Clear, ClearType},
    QueueableCommand,
};
use e2ee_rust_client_lib::Client;
use e2ee_rust_common::{
    crypto::{curve::curve25519::Curve25519, pqkem::crystalskyber512::CrystalsKyber512},
    storage::client::traits::ClientStorage,
};
use e2ee_rust_common::{
    errors::general::{GeneralError, ToGeneralError},
    storage::storage_interface::StorageInterface,
};
use e2ee_rust_sqlite_storage::SQLiteStorage;

// curve        A Montgomery curve for which XEdDSA is specified, at present this is one of curve25519 or curve448
const CURVE_TYPE: Curve25519 = Curve25519 {};

// hash         A 256 or 512-bit hash function (e.g. SHA-256 or SHA-512)
// const HASH_TYPE: HashType = HashType::SHA256;

// info         An optional ASCII string with a maximum length of 255 bytesAn ASCII string identifying the application with a minimum length of 8 bytes
// const INFO: &str = "PQXDHTestApplication";

// pqkem        A post-quantum key encapsulation mechanism that has IND-CCA post-quantum security (e.g. Crystals-Kyber-1024)
const PQKEM_TYPE: CrystalsKyber512 = CrystalsKyber512 {};

// aead         A scheme for authenticated encryption with associated data that has IND-CPA and INT-CTXT post-quantum security
// const AEAD_TYPE: AES256GCM = AES256GCM {};

fn clear_screen(out: &mut Stdout) {
    out.queue(Hide).unwrap();
    out.queue(Clear(ClearType::All)).unwrap();
    out.queue(MoveTo(0, 0)).unwrap();
    out.flush().unwrap();
}

fn main() -> Result<(), GeneralError> {
    // Stdout output
    let mut out = stdout();

    // Initialize the storage
    let client_storage = SQLiteStorage::new("test-client", "./").to_general_error()?;
    println!("Client storage created");

    // Initializes the client storage
    client_storage.init_client().to_general_error()?;
    println!("Client storage initialized");

    // Start the client
    let _client = Client::new(client_storage, CURVE_TYPE, PQKEM_TYPE)?;

    // Print the greet message
    clear_screen(&mut out);
    println!("Client ready");

    // Wait for the user to press enter
    println!("Press enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    Ok(())
}
