use e2ee_rust_common::{
    crypto::{
        curve::{
            curve25519::Curve25519,
            keys::{IdentifiedEllipticCurveKeyPair, IdentifiedEllipticCurvePublicKey},
            traits::EllipticCurveAlgorithm,
        },
        pqkem::{
            crystalskyber512::CrystalsKyber512,
            keys::{IdentifiedPQKEMKeyPair, IdentifiedPQKEMPublicKey},
            traits::PQKEMAlgorithm,
        },
    },
    errors::{general::{GeneralError, ToGeneralError}, zmq::ZMQError},
    messages::{
        client::{
            client_hello::ClientHello,
            client_message::{ClientMessage, ClientMessageType},
            new_keys::{NewKeys, NewKeysType},
        },
        server::server_message::{ServerCommand, ServerMessageType},
    },
    pqxdh::{
        one_time_curve_prekey_set::OneTimeCurvePrekeySet, private_bundle::PrivateBundle,
        registration_bundle::RegistrationBundle, signed_curve_prekey::SignedCurvePrekey,
        signed_one_time_pqkem_prekey_set::SignedOneTimePqkemPrekeySet,
        signed_pqkem_prekey::SignedPQKEMPrekey,
    },
    protobuf::utils::{create_client_message, decode_server_message},
    storage::{client::traits::ClientStorage, storage_interface::StorageInterface},
};
use e2ee_rust_sqlite_storage::SQLiteStorage;
use log::{debug, error, info};
use uuid::Uuid;

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

const ONE_TIME_CURVE_PREKEYS: usize = 10;
const ONE_TIME_PQKEM_PREKEYS: usize = 10;

const ENDPOINT: &str = "tcp://localhost:5555";

fn get_client_id(
    cached_client_id: &mut Option<Uuid>,
    client_storage: &impl ClientStorage,
) -> Result<Uuid, GeneralError> {
    if let Some(client_id) = cached_client_id {
        Ok(*client_id)
    } else {
        let storage_client_id = client_storage
            .get_client_uuid()
            .to_general_error()?;
        *cached_client_id = Some(storage_client_id);
        Ok(storage_client_id)
    }
}

fn get_private_bundle(client_storage: &impl ClientStorage) -> Result<PrivateBundle, GeneralError> {
    let private_bundle = client_storage
        .get_private_key_bundle()
        .to_general_error()?;
    Ok(private_bundle)
}

fn main() -> Result<(), GeneralError> {
    env_logger::init();

    // Cache
    let mut cached_client_id: Option<Uuid> = None;

    // Initialize the storage
    let mut client_storage = SQLiteStorage::new(
        "test-client",
        "./",
    )
    .to_general_error()?;
    info!("Client storage created");

    // Initializes the client storage
    client_storage
        .init_client()
        .to_general_error()?;
    info!("Client storage initialized");

    // Check if the client is already registered
    if client_storage
        .contains_client()
        .to_general_error()?
        .is_some()
    {
        debug!("Client already registered in storage");
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
        info!("Generated private bundle");

        // Generate the client uuid
        let client_uuid = Uuid::new_v4();
        info!("Generated client uuid: {}", client_uuid);

        // Store the client in the storage
        client_storage
            .create_client(&client_uuid, &private_key_bundle)
            .to_general_error()?;
    }

    // Start a request socket
    info!(
        "Starting client with identity {}...",
        get_client_id(&mut cached_client_id, &client_storage)?
    );
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::DEALER).unwrap();
    socket
        .set_identity(get_client_id(&mut cached_client_id, &client_storage)?.as_bytes())
        .map_err(|_| GeneralError::ZMQ(ZMQError::SetIdentityError))?;

    // Connect to the server
    info!("Connecting to server...");
    socket
        .connect(ENDPOINT)
        .map_err(|_| GeneralError::ZMQ(ZMQError::ConnectError))?;

    // Connection flow

    // Client sends the client hello
    let mut message: ClientMessage = ClientMessage::new(
        ClientMessageType::ClientHello,
        get_client_id(&mut cached_client_id, &client_storage)?,
    );
    message.client_hello = Some(ClientHello {});
    socket
        .send("", zmq::SNDMORE)
        .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
    debug!("Sent envelope delimiter");
    socket
        .send(create_client_message(&message), 0)
        .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
    info!("Sent client hello message");

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
        info!("Received server message: {:?}", server_message);

        // Handle server message
        match server_message.message_type {
            ServerMessageType::Ok => {
                info!("Server OK");
                break;
            }
            ServerMessageType::Error => {
                error!("Server error: {:?}", server_message.error.unwrap());
                return Err(GeneralError::ServerError);
            }
            ServerMessageType::Command => {
                let client_response = handle_server_command(
                    &server_message.command.unwrap(),
                    get_client_id(&mut cached_client_id, &client_storage)?,
                    &mut client_storage,
                );
                if client_response.is_err() {
                    error!(
                        "Error handling server command: {:?}",
                        client_response.err().unwrap()
                    );
                    break;
                }
                socket
                    .send("", zmq::SNDMORE)
                    .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
                debug!("Sent envelope delimiter");
                socket
                    .send(create_client_message(&client_response.unwrap()), 0)
                    .map_err(|_| GeneralError::ZMQ(ZMQError::SendError))?;
                info!("Sent client response");
            }
        }
    }

    // Disconnect socket
    if socket.disconnect(ENDPOINT).is_err() {
        error!("Error disconnecting socket");
    } else {
        info!("Disconnected socket");
    }

    Ok(())
}

fn handle_server_command(
    server_command: &ServerCommand,
    client_id: Uuid,
    client_storage: &mut impl ClientStorage,
) -> Result<ClientMessage, GeneralError> {
    debug!("Handling server command: {:?}", server_command);
    match server_command {
        ServerCommand::AskForRegistrationBundle => {
            debug!("Generating registration bundle from private bundle");
            let mut rng = rand::thread_rng();
            let mut msg = ClientMessage::new(ClientMessageType::RegistrationBundle, client_id);
            msg.registration_bundle = Some(RegistrationBundle::from_private_bundle(
                &get_private_bundle(client_storage)?,
                &CURVE_TYPE,
                &mut rng,
            )?);
            Ok(msg)
        }
        ServerCommand::AskForNewSPK => {
            debug!("Generating new signed prekey");

            // Generate a new curve signed prekey and the signature
            let mut rng = rand::thread_rng();
            let new_signed_prekey: IdentifiedEllipticCurveKeyPair =
                CURVE_TYPE.generate_identified_key_pair(&mut rng);
            let signature = CURVE_TYPE
                .xeddsa_sign(
                    &get_private_bundle(client_storage)?.identity_key.private_key,
                    &new_signed_prekey.key_pair.public_key.encode_ec(),
                    &mut rng,
                )
                .map_err(|e| GeneralError::XedDSA(e))?;
            debug!(
                "Generated new signed prekey: {}",
                new_signed_prekey.key_pair.public_key.print_key()
            );

            // Store it in the private bundle
            client_storage
                .update_curve_signed_prekey(&new_signed_prekey)
                .map_err(|e| {
                    error!("Failed to update signed prekey: {:?}", e);
                    GeneralError::StorageError(e)
                })?;
            debug!("Updated signed prekey");

            // Return the message
            let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client_id);
            msg.new_keys = Some(NewKeys {
                keys_type: NewKeysType::SignedCurvePrekey,
                signed_curve_prekey: Some(SignedCurvePrekey {
                    identified_public_key:
                        IdentifiedEllipticCurvePublicKey::from_identified_key_pair(
                            &new_signed_prekey,
                        ),
                    signature,
                }),
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: None,
            });

            Ok(msg)
        }
        ServerCommand::AskForNewCOPK => {
            debug!("Generating new one time curve prekeys");

            // Generate a new set of curve one time prekeys
            let mut rng = rand::thread_rng();
            let new_keys: Vec<IdentifiedEllipticCurveKeyPair> = (0..ONE_TIME_CURVE_PREKEYS)
                .into_iter()
                .map(|_| CURVE_TYPE.generate_identified_key_pair(&mut rng))
                .collect();

            // Store it in the private bundle
            client_storage
                .add_curve_one_time_prekeys(&new_keys)
                .map_err(|e| {
                    error!("Failed to add curve one time prekeys: {:?}", e);
                    GeneralError::StorageError(e)
                })?;
            debug!("Added {} new one time curve prekeys", new_keys.len());

            // Return the message
            let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client_id);
            msg.new_keys = Some(NewKeys {
                keys_type: NewKeysType::OneTimeCurvePrekeySet,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: Some(OneTimeCurvePrekeySet {
                    prekeys: new_keys
                        .iter()
                        .map(|k| IdentifiedEllipticCurvePublicKey::from_identified_key_pair(k))
                        .collect(),
                }),
                signed_one_time_pqkem_prekey_set: None,
            });

            Ok(msg)
        }
        ServerCommand::AskForNewLastResortPQKEMPrekey => {
            debug!("Generating new signed last resort pqkem prekey");

            // Generate a new signed pqkem prekey and the signature
            let mut rng = rand::thread_rng();
            let new_last_resort_prekey = PQKEM_TYPE.generate_identified_key_pair(&mut rng);
            let signature = CURVE_TYPE
                .xeddsa_sign(
                    &get_private_bundle(client_storage)?.identity_key.private_key,
                    &new_last_resort_prekey.key_pair.public_key.encode_kem(),
                    &mut rng,
                )
                .map_err(|e| GeneralError::XedDSA(e))?;

            // Store it in the private bundle
            client_storage
                .update_last_resort_pqkem_prekey(&new_last_resort_prekey)
                .map_err(|e| {
                    error!("Failed to update last resort pqkem prekey: {:?}", e);
                    GeneralError::StorageError(e)
                })?;
            debug!("Updated last resort pqkem prekey");

            // Return the message
            let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client_id);
            msg.new_keys = Some(NewKeys {
                keys_type: NewKeysType::SignedLastResortPQKEMPrekey,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: Some(SignedPQKEMPrekey {
                    identified_public_key: IdentifiedPQKEMPublicKey::from_identified_key_pair(
                        &new_last_resort_prekey,
                    ),
                    signature,
                }),
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: None,
            });

            Ok(msg)
        }
        ServerCommand::AskForNewPQOPK => {
            debug!("Generating new set of signed pqkem prekeys");

            // Generate a new set of pqkem one time prekeys
            let mut rng = rand::thread_rng();
            let new_keys: Vec<IdentifiedPQKEMKeyPair> = (0..ONE_TIME_PQKEM_PREKEYS)
                .into_iter()
                .map(|_| PQKEM_TYPE.generate_identified_key_pair(&mut rng))
                .collect();
            let signatures: Vec<[u8; 64]> = new_keys
                .clone()
                .into_iter()
                .map(|k| {
                    CURVE_TYPE
                        .xeddsa_sign(
                            &get_private_bundle(client_storage)?.identity_key.private_key,
                            &k.key_pair.public_key.encode_kem(),
                            &mut rng,
                        )
                        .map_err(|e| GeneralError::XedDSA(e))
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Append them to the current one time prekeys
            client_storage
                .add_signed_pqkem_prekeys(&new_keys)
                .map_err(|e| {
                    error!("Failed to add signed one time PQKEM prekeys: {:?}", e);
                    GeneralError::StorageError(e)
                })?;
            debug!("Added {} new signed one time PQKEM prekeys", new_keys.len());

            // Return the message
            let mut msg = ClientMessage::new(ClientMessageType::NewKeys, client_id);
            msg.new_keys = Some(NewKeys {
                keys_type: NewKeysType::SignedOneTimePQKEMPrekeySet,
                signed_curve_prekey: None,
                signed_last_resort_pqkem_prekey: None,
                one_time_curve_prekey_set: None,
                signed_one_time_pqkem_prekey_set: Some(SignedOneTimePqkemPrekeySet {
                    prekeys: new_keys
                        .iter()
                        .enumerate()
                        .map(|(i, k)| SignedPQKEMPrekey {
                            identified_public_key:
                                IdentifiedPQKEMPublicKey::from_identified_key_pair(k),
                            signature: signatures[i],
                        })
                        .collect(),
                }),
            });

            Ok(msg)
        }
    }
}
