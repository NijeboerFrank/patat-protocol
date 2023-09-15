use snow::{Builder, Keypair};

use crate::{handshake, patat_connection::PatatConnection};

pub fn run_server(protocol_builder: Builder, keys: Keypair) {
    let server_static_key = keys.private;
    let connection = PatatConnection::new("127.0.0.1:5071".to_owned(), 5072);

    let mut transport_protocol =
        handshake::run_server_handshake(protocol_builder, server_static_key, &connection);

    let mut payload_buffer = vec![0u8; 65535];
    let message = &connection.receive_data().expect("Could not receive data");
    let payload_length = transport_protocol
        .read_message(&message, &mut payload_buffer)
        .unwrap();
    println!(
        "{:?}",
        String::from_utf8_lossy(&payload_buffer[..payload_length])
    );
}
