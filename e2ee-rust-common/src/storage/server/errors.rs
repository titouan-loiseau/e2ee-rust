#[derive(Debug, Clone)]
pub enum ServerStorageError {
    ClientNotFound,
    ClientAlreadyExists,
    KeyBundleNotFound,
    EllipticCurvePublicKeyNotFound,
    IdentifiedEllipticCurvePublicKeyNotFound,
    SignedCurvePrekeyNotFound,
    PQKEMPublicKeyNotFound,
    IdentifiedPQKEMPublicKeyNotFound,
    SignedPQKEMPrekeyNotFound,
}
