extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &[
            "src/protobuf/crypto/curve/types.proto",
            "src/protobuf/crypto/curve/keys.proto",
            "src/protobuf/crypto/pqkem/types.proto",
            "src/protobuf/crypto/pqkem/keys.proto",
            "src/protobuf/pqxdh/pb_signed_curve_prekey.proto",
            "src/protobuf/pqxdh/pb_signed_pqkem_prekey.proto",
            "src/protobuf/pqxdh/pb_one_time_curve_prekey_set.proto",
            "src/protobuf/pqxdh/pb_signed_one_time_pqkem_prekey_set.proto",
            "src/protobuf/pqxdh/pb_registration_bundle.proto",
            "src/protobuf/client/pb_client_message.proto",
            "src/protobuf/client/pb_client_hello.proto",
            "src/protobuf/client/pb_new_keys.proto",
            "src/protobuf/client/pb_request_peer_bundle.proto",
            "src/protobuf/server/pb_server_message.proto",
        ],
        &["src/protobuf/"],
    )
    .unwrap();
}
