pub mod crypto;
pub mod utils;

pub mod pqxdh {
    include!(concat!(env!("OUT_DIR"), "/pqxdh.rs"));
}

pub mod client {
    include!(concat!(env!("OUT_DIR"), "/client.rs"));
}

pub mod server {
    include!(concat!(env!("OUT_DIR"), "/server.rs"));
}
