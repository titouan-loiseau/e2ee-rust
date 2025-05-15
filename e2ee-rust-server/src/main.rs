use e2ee_rust_common::{
    errors::{general::GeneralError, zmq::ZMQError},
    messages::{
        client::{
            client_hello::ClientHello,
            client_message::{ClientMessage, ClientMessageType},
            new_keys::{NewKeys, NewKeysType},
        },
        server::server_message::{ServerCommand, ServerError, ServerMessage},
    },
    pqxdh::registration_bundle::RegistrationBundle,
    protobuf::utils::{create_server_message, decode_client_message},
    storage::{
        server::{
            client_structs::{ClientInformation, ClientKeyBundle},
            traits::ServerStorage,
        },
        storage_interface::StorageInterface,
    },
    utils::display::print_slice,
};
use e2ee_rust_sqlite_storage::SQLiteStorage;
use log::{debug, error, info, warn};
use uuid::Uuid;

const ENDPOINT: &str = "tcp://*:5555";
const MONITOR_ENDPOINT: &str = "inproc://monitor.rep";

// const CURVE_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;
const CURVE_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60;
// const PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;
const PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS: u64 = 60;
const CURVE_ONE_TIME_PREKEYS_THRESHOLD: usize = 5;
const PQKEM_ONE_TIME_PREKEYS_THRESHOLD: usize = 5;

enum KeysCheckResult {
    Ok,
    NewSPK,
    NewLRSPK,
    NewCOPK,
    NewPQOPK,
}

fn main() -> Result<(), GeneralError> {
    env_logger::init();

    // Create the server storage
    let mut server_storage = SQLiteStorage::new(
        "test-server",
        "./",
    )
    .map_err(|e| GeneralError::StorageError(e))?;
    info!("Server storage created");

    // Initializes the server storage
    server_storage
        .init_server()
        .map_err(|e| GeneralError::StorageError(e))?;
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

fn handle_client_message(
    client_message: &ClientMessage,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    match client_message.message_type {
        ClientMessageType::ClientHello => {
            let client_hello = client_message.client_hello.as_ref().unwrap();
            handle_client_hello(client_message.client_id, client_hello, server_storage)
        }
        ClientMessageType::RegistrationBundle => {
            let registration_bundle = client_message.registration_bundle.as_ref().unwrap();
            handle_registration_bundle(
                client_message.client_id,
                registration_bundle,
                server_storage,
            )
        }
        ClientMessageType::NewKeys => {
            let new_keys = client_message.new_keys.as_ref().unwrap();
            handle_new_keys(client_message.client_id, new_keys, server_storage)
        }
    }
}

fn handle_client_hello(
    client_id: Uuid,
    _client_hello: &ClientHello,
    server_storage: &impl ServerStorage,
) -> ServerMessage {
    debug!("Handling client hello from client_id: {}", client_id);

    // Check if the client is registered
    if let Ok(client_info) = server_storage.get_client(&client_id) {
        // Get the keys and check them
        return state_check_keys(client_id, &client_info.key_bundle, server_storage);
    }

    // Client is not registered, ask for registration bundle
    debug!("Client is not registered, asking for registration bundle");
    return ServerMessage::new_command(ServerCommand::AskForRegistrationBundle);
}

fn state_check_keys(
    client_id: Uuid,
    bundle: &ClientKeyBundle,
    server_storage: &impl ServerStorage,
) -> ServerMessage {
    let state = check_keys(bundle);

    match state {
        KeysCheckResult::Ok => send_first_messages(client_id, server_storage),
        KeysCheckResult::NewSPK => {
            debug!("Asking for new SPK");
            ServerMessage::new_command(ServerCommand::AskForNewSPK)
        }
        KeysCheckResult::NewLRSPK => {
            debug!("Asking for new last resort PQKEM prekey");
            ServerMessage::new_command(ServerCommand::AskForNewLastResortPQKEMPrekey)
        }
        KeysCheckResult::NewCOPK => {
            debug!("Asking for new curve one time prekeys");
            ServerMessage::new_command(ServerCommand::AskForNewCOPK)
        }
        KeysCheckResult::NewPQOPK => {
            debug!("Asking for new PQKEM one time prekeys");
            ServerMessage::new_command(ServerCommand::AskForNewPQOPK)
        }
    }
}

fn check_keys(bundle: &ClientKeyBundle) -> KeysCheckResult {
    debug!("Checking keys");
    let now = chrono::Utc::now();

    // Check if the curve signed prekey is expired
    if now
        .signed_duration_since(bundle.signed_curve_prekey.1)
        .as_seconds_f32() as u64
        > CURVE_SIGNED_PREKEY_LIFETIME_SECS
    {
        debug!("Curve signed prekey is expired");
        return KeysCheckResult::NewSPK;
    }

    // Check if the last resort PQKEM signed prekey is expired
    if now
        .signed_duration_since(bundle.signed_last_resort_pqkem_prekey.1)
        .as_seconds_f32() as u64
        > PQKEM_LAST_RESORT_SIGNED_PREKEY_LIFETIME_SECS
    {
        debug!("Last resort PQKEM signed prekey is expired");
        return KeysCheckResult::NewLRSPK;
    }

    // Check if we are running low on curve one time prekeys
    if bundle.one_time_curve_prekeys.prekeys.len() < CURVE_ONE_TIME_PREKEYS_THRESHOLD {
        debug!("Running low on curve one time prekeys");
        return KeysCheckResult::NewCOPK;
    }

    // Check if we are running low on PQKEM one time prekeys
    if bundle.signed_one_time_pqkem_prekeys.prekeys.len() < PQKEM_ONE_TIME_PREKEYS_THRESHOLD {
        debug!("Running low on PQKEM one time prekeys");
        return KeysCheckResult::NewPQOPK;
    }

    // All keys are fine
    debug!("All keys are fine");
    return KeysCheckResult::Ok;
}

fn send_first_messages(_client_id: Uuid, _server_storage: &impl ServerStorage) -> ServerMessage {
    // TODO: Implement this function
    debug!("Sending first messages");
    ServerMessage::new_ok()
}

fn handle_registration_bundle(
    client_id: Uuid,
    registration_bundle: &RegistrationBundle,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    debug!("Handling registration bundle");

    // Make sure that the client is not already registered
    if server_storage.get_client(&client_id).is_ok() {
        return ServerMessage::new_error(ServerError::ClientAlreadyRegistered);
    }

    // Create the client key bundle
    let now = chrono::Utc::now();
    let client_key_bundle = ClientKeyBundle {
        identity_key: (registration_bundle.identity_key.clone(), now),
        signed_curve_prekey: (registration_bundle.signed_curve_prekey.clone(), now),
        signed_last_resort_pqkem_prekey: (
            registration_bundle.signed_last_resort_pqkem_prekey.clone(),
            now,
        ),
        one_time_curve_prekeys: registration_bundle.one_time_curve_prekeys.clone(),
        signed_one_time_pqkem_prekeys: registration_bundle.one_time_pqkem_prekeys.clone(),
    };

    // Add the client to the server storage
    if let Err(e) = server_storage.add_client(
        client_id,
        &ClientInformation {
            key_bundle: client_key_bundle.clone(),
        },
    ) {
        error!("Error adding client: {:?}", e);
        return ServerMessage::new_error(ServerError::UnknownError);
    }

    // Check the keys
    state_check_keys(client_id, &client_key_bundle, server_storage)
}

fn handle_new_keys(
    client_id: Uuid,
    new_keys: &NewKeys,
    server_storage: &mut impl ServerStorage,
) -> ServerMessage {
    debug!("Handling new keys");

    // Make sure that the client is registered
    let client_bundle: ClientInformation;

    // Get the client bundle as mut
    match server_storage.get_client(&client_id) {
        Ok(client) => client_bundle = client,
        Err(_) => return ServerMessage::new_error(ServerError::ClientNotRegistered),
    }

    // Update the keys as needed
    let now = chrono::Utc::now();
    let res: Result<(), ServerError> = match new_keys.keys_type {
        NewKeysType::SignedCurvePrekey => {
            debug!("Updating the signed curve prekey");
            if let Some(new_key) = &new_keys.signed_curve_prekey {
                server_storage
                    .update_signed_curve_prekey(client_id, new_key, &now)
                    .map_err(|e| {
                        error!(
                            "Error updating the key bundle's signed curve prekey: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::SignedLastResortPQKEMPrekey => {
            debug!("Updating the last resort PQKEM prekey");
            if let Some(new_key) = &new_keys.signed_last_resort_pqkem_prekey {
                server_storage
                    .update_signed_last_resort_pqkem_prekey(client_id, new_key, &now)
                    .map_err(|e| {
                        error!(
                            "Error updating the key bundle's signed last resort PQKEM prekey: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::OneTimeCurvePrekeySet => {
            debug!("Adding new one time curve prekeys");
            if let Some(new_keys) = &new_keys.one_time_curve_prekey_set {
                server_storage
                    .add_one_time_curve_prekeys(client_id, new_keys)
                    .map_err(|e| {
                        error!(
                            "Error adding one time curve prekeys to the key bundle: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
        NewKeysType::SignedOneTimePQKEMPrekeySet => {
            debug!("Adding new signed one time PQKEM prekeys");
            if let Some(new_keys) = &new_keys.signed_one_time_pqkem_prekey_set {
                server_storage
                    .add_signed_one_time_pqkem_prekeys(client_id, new_keys)
                    .map_err(|e| {
                        error!(
                            "Error adding signed one time PQKEM prekeys to the key bundle: {:?}",
                            e
                        );
                        ServerError::UnknownError
                    })
            } else {
                Err(ServerError::BadResponse)
            }
        }
    };
    if let Err(err) = res {
        return ServerMessage::new_error(err);
    }
    debug!("Update OK");

    state_check_keys(client_id, &client_bundle.key_bundle, server_storage)
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
