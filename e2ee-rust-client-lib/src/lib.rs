mod commands;

use std::{
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use commands::handler::handle_server_command;
use e2ee_rust_common::{
    crypto::{
        curve::{curve25519::Curve25519, traits::EllipticCurveAlgorithm},
        pqkem::{crystalskyber512::CrystalsKyber512, traits::PQKEMAlgorithm},
    },
    errors::{
        general::{GeneralError, ToGeneralError},
        zmq::ZMQError,
    },
    messages::{
        client::{
            client_hello::ClientHello,
            client_message::{ClientMessage, ClientMessageType},
        },
        server::server_message::ServerMessageType,
    },
    pqxdh::private_bundle::PrivateBundle,
    protobuf::utils::{create_client_message, decode_server_message},
    storage::client::traits::ClientStorage,
};
use log::{debug, error, info};
use uuid::Uuid;
use zmq::Socket;

pub struct ClientData<
    T: EllipticCurveAlgorithm + Send,
    U: PQKEMAlgorithm + Send,
    S: ClientStorage + Send,
> {
    client_uuid: Uuid,
    client_storage_mutex: Mutex<S>,
    socket_mutex: Mutex<Socket>,
    curve_algorithm: T,
    pqkem_algorithm: U,
}

pub struct Client<
    T: EllipticCurveAlgorithm + Send,
    U: PQKEMAlgorithm + Send,
    S: ClientStorage + Send,
> {
    client_data: Arc<ClientData<T, U, S>>,
    heartbeat_thread: Option<JoinHandle<()>>,
}

// TODO: parameterize
const CURVE_TYPE: Curve25519 = Curve25519 {};
const PQKEM_TYPE: CrystalsKyber512 = CrystalsKyber512 {};

const ONE_TIME_CURVE_PREKEYS: usize = 10;
const ONE_TIME_PQKEM_PREKEYS: usize = 10;

// TODO: parameterize
const ENDPOINT: &str = "tcp://localhost:5555";

impl<T, U, S> Client<T, U, S>
where
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
{
    // Starts the client in a separate thread and returns the client handle when the client is ready (connected to the server and registered and heartbeat is running)
    pub fn new(
        client_storage: S,
        curve_algorithm: T,
        pqkem_algorithm: U,
    ) -> Result<Self, GeneralError> {
        env_logger::init();

        debug!("Starting client");

        // Get the UUID from the storage initialization
        let client_uuid = initialize_client_storage(&client_storage)?;
        debug!("Client UUID: {}", client_uuid);

        // Connect to the server
        let socket = connect_to_server(client_uuid)?;
        debug!("Connected to server");

        let socket_mutex = Mutex::new(socket);
        let client_storage_mutex = Mutex::new(client_storage);

        // Create the client
        let client = ClientData {
            client_uuid,
            client_storage_mutex,
            socket_mutex,
            curve_algorithm,
            pqkem_algorithm,
        };

        // Start the heartbeat thread
        let client_arc = Arc::new(client);
        let client_arc_clone = Arc::clone(&client_arc);

        let thread_handle = std::thread::spawn(move || loop {
            debug!("Sending server heartbeat");
            if let Err(e) = server_heartbeat(&client_arc_clone) {
                error!("Error in server heartbeat: {}", e);
                break;
            };

            // Sleep for 1 second between heartbeats
            thread::sleep(Duration::from_secs(1));
        });

        // Return the client
        Ok(Client {
            client_data: Arc::clone(&client_arc),
            heartbeat_thread: Some(thread_handle),
        })
    }
}

fn initialize_client_storage<S: ClientStorage>(client_storage: &S) -> Result<Uuid, GeneralError> {
    let client_uuid: Uuid;

    // Check if the client is already registered
    if client_storage
        .contains_client()
        .to_general_error()?
        .is_some()
    {
        debug!("Client already registered in storage");
        client_uuid = client_storage.get_client_uuid().to_general_error()?;
    } else {
        info!("Client not registered in storage, registering...");
        let mut rng = rand::thread_rng();

        // Generate the private bundle
        let private_key_bundle = PrivateBundle::new(
            &CURVE_TYPE,
            &PQKEM_TYPE,
            ONE_TIME_CURVE_PREKEYS,
            ONE_TIME_PQKEM_PREKEYS,
            &mut rng,
        );
        debug!("Generated private bundle");

        // Generate the client uuid
        client_uuid = Uuid::new_v4();
        debug!("Generated client uuid: {}", client_uuid);

        // Store the client in the storage
        client_storage
            .create_client(&client_uuid, &private_key_bundle)
            .to_general_error()?;
    }
    Ok(client_uuid)
}

fn connect_to_server(client_uuid: Uuid) -> Result<Socket, GeneralError> {
    // Start a request socket
    info!("Starting client with identity {}...", client_uuid);
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::DEALER).unwrap();
    socket
        .set_identity(client_uuid.as_bytes())
        .map_err(|_| GeneralError::ZMQ(ZMQError::SetIdentityError))?;

    // Connect to the server
    info!("Connecting to server...");
    socket
        .connect(ENDPOINT)
        .map_err(|_| GeneralError::ZMQ(ZMQError::ConnectError))?;

    Ok(socket)
}

fn server_heartbeat<
    T: EllipticCurveAlgorithm + Send + Sync + 'static,
    U: PQKEMAlgorithm + Send + Sync + 'static,
    S: ClientStorage + Send + Sync + 'static,
>(
    client: &Arc<ClientData<T, U, S>>,
) -> Result<(), GeneralError> {
    // Get the socket
    let socket = client.socket_mutex.lock().unwrap();

    // Client sends the client hello
    let mut message: ClientMessage =
        ClientMessage::new(ClientMessageType::ClientHello, client.client_uuid);
    message.client_hello = Some(ClientHello {});
    socket
        .send("", zmq::SNDMORE)
        .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
    debug!("Sent envelope delimiter");
    socket
        .send(create_client_message(&message), 0)
        .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
    debug!("Sent client hello message");

    // Answer commands until we get an OK or an error
    loop {
        // Wait for envelope delimiter
        socket
            .recv_bytes(0)
            .map_err(|_| GeneralError::ZMQ(ZMQError::RecvError))?;

        // Wait for server message
        let server_response = socket
            .recv_bytes(0)
            .map_err(|_| GeneralError::ZMQ(ZMQError::RecvError))?;
        let server_message =
            decode_server_message(&server_response).map_err(|e| GeneralError::Protobuf(e))?;
        debug!("Received server message: {:?}", server_message);

        // Handle server message
        match server_message.message_type {
            ServerMessageType::Ok => {
                debug!("Server OK");
                break;
            }
            ServerMessageType::Error => {
                error!("Server error: {:?}", server_message.error.unwrap());
                return Err(GeneralError::ServerError);
            }
            ServerMessageType::Command => {
                let client_response =
                    handle_server_command(&server_message.command.unwrap(), client);
                if client_response.is_err() {
                    error!(
                        "Error handling server command: {:?}",
                        client_response.err().unwrap()
                    );
                    return Err(GeneralError::ClientError);
                }
                socket
                    .send("", zmq::SNDMORE)
                    .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
                debug!("Sent envelope delimiter");
                socket
                    .send(create_client_message(&client_response.unwrap()), 0)
                    .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
                debug!("Sent client response");
            }
        }
    }

    Ok(())
}
