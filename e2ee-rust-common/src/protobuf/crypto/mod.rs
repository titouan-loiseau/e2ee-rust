pub mod curve {
    include!(concat!(env!("OUT_DIR"), "/crypto.curve.rs"));
}

pub mod pqkem {
    include!(concat!(env!("OUT_DIR"), "/crypto.pqkem.rs"));
}
