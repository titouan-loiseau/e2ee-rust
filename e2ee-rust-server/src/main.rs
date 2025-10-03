mod handles;
mod utils;

use e2ee_rust_common::{
    errors::{
        general::{GeneralError, ToGeneralError},
        zmq::ZMQError,
    },
    messages::server::server_message::{ServerError, ServerMessage},
    protobuf::utils::{create_server_message, decode_client_message},
    storage::{server::traits::ServerStorage, storage_interface::StorageInterface},
    utils::display::print_slice,
};
use e2ee_rust_sqlite_storage::SQLiteStorage;
use handles::client_message::handle_client_message;
use log::{debug, error, info, warn};

const ENDPOINT: &str = "tcp://*:5555";
const MONITOR_ENDPOINT: &str = "inproc://monitor.rep";

// const CURVE_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;
const CURVE_SIGNED_PREKEY_LIFETIME_SECS: u64 = 10;
// const PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;
const PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS: u64 = 10;
const CURVE_ONE_TIME_PREKEYS_THRESHOLD: usize = 5;
const PQKEM_ONE_TIME_PREKEYS_THRESHOLD: usize = 5;

fn main() -> Result<(), GeneralError> {
    env_logger::init();

    // Create the server storage
    let mut server_storage = SQLiteStorage::new("test-server", "./").to_general_error()?;
    info!("Server storage created");

    // Initializes the server storage
    server_storage.init_server().to_general_error()?;
    info!("Server storage initialized");

    // Prepare our context and socket
    let ctx = zmq::Context::new();

    // Create the server reply socket
    info!("Creating server socket...");
    let server_socket = ctx.socket(zmq::ROUTER).unwrap();
    server_socket
        .monitor(MONITOR_ENDPOINT, zmq::SocketEvent::ALL as i32)
        .map_err(|_| GeneralError::ZMQ(ZMQError::MonitorError))?;

    // Create the monitor socket in a separate thread
    info!("Creating monitor socket...");
    let ctx_clone = ctx.clone();
    std::thread::spawn(move || {
        monitor(&ctx_clone).unwrap();
    });

    // Bind the server socket to the endpoint
    info!("Starting server...");
    server_socket
        .bind(ENDPOINT)
        .map_err(|_| GeneralError::ZMQ(ZMQError::SocketBindError))?;

    info!("Server started, waiting for requests...");

    // Start the server loop
    loop {
        // Wait for next request from client
        let identity = server_socket
            .recv_bytes(0)
            .map_err(|_| GeneralError::ZMQ(ZMQError::RecvError))?;
        info!("Received: message from {}", print_slice(&identity));
        server_socket.send(&identity, zmq::SNDMORE).unwrap();

        // Wait for envelope
        // If the envelope is an error or if it is not an empty message, the communication is not correct, so we skip it
        let envelope = server_socket.recv_bytes(zmq::SNDMORE);
        if envelope.is_err() || envelope.unwrap().len() != 0 {
            warn!("Received: invalid envelope");
            continue;
        }

        // Wait for message
        let msg = server_socket.recv_bytes(0);
        if msg.is_err() {
            error!("Error receiving message");
            continue;
        }

        // Try to convert the message to a ClientMessage
        let server_message_res = decode_client_message(&msg.unwrap());
        let answer: ServerMessage = match server_message_res {
            Ok(server_message) => {
                debug!("Decoded client message");
                handle_client_message(&server_message, &mut server_storage)
            }
            Err(e) => {
                error!("Error decoding client message: {:?}", e);
                ServerMessage::new_error(ServerError::CannotDecodeClientMessage)
            }
        };

        // Respond to client
        let mut err = server_socket.send("", zmq::SNDMORE);
        if err.is_ok() {
            err = server_socket.send(create_server_message(&answer), 0);
        }
        if err.is_err() {
            error!("Error sending message");
        }
    }
}

fn monitor(ctx: &zmq::Context) -> Result<(), zmq::Error> {
    let socket = ctx.socket(zmq::PAIR)?;
    socket.connect(MONITOR_ENDPOINT)?;
    info!("Monitor started");

    loop {
        // Get the event ID and translate it into a SocketEvent
        let eventid_msg = socket.recv_msg(0)?;
        let event = u16::from_ne_bytes([eventid_msg[0], eventid_msg[1]]);
        let zmq_event = zmq::SocketEvent::from_raw(event);

        // Get the address of the socket that triggered the event
        assert!(socket.get_rcvmore()?, "Expected more event parts");
        let addr_msg = socket.recv_msg(0)?;
        let addr = String::from_utf8(addr_msg.to_vec()).unwrap();

        info!("Monitor received: {:?} on {}", zmq_event, addr);
    }
}
