#[derive(Debug)]
pub enum ZMQError {
    SocketBindError,
    ConnectError,
    RecvError,
    SendError,
    MonitorError,
    SetIdentityError,
}
