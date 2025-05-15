#[derive(Debug)]
pub enum ProtobufError {
    DecodeError(prost::DecodeError),
    MissingMessageType,
    MissingField(&'static str),
    InvalidField(&'static str),
    InvalidFieldLength(&'static str, usize, usize),
    WrongBufferSize,
}
