use snow::{Builder, Keypair};

use crate::patat_connection::PatatConnection;

pub fn run_server(protocol_builder: Builder, keys: Keypair) {
    let server_static_key = keys.private;
    let mut protocol = protocol_builder
        .local_private_key(&server_static_key)
        .build_responder()
        .expect("Could not start protocol");

    let connection = PatatConnection::new("127.0.0.1:5071".to_owned(), 5072);

    // -> e, es
    let message = &connection.receive_data().expect("Could not receive data");
    let mut payload_buffer = vec![0u8; 65535];
    let payload_length = protocol
        .read_message(&message, &mut payload_buffer)
        .expect("Couldn't process message");
    println!("Payload was {:?}", &payload_buffer[..payload_length]);

    // <- e, ee
    let mut buf = vec![0u8; 65535];
    let message_len = protocol
        .write_message(&[1], &mut buf)
        .expect("Something went wrong with creating a new message");
    connection.send_data(&buf[..message_len]).unwrap();

    // -> s, se
    let message = &connection.receive_data().expect("Could not receive data");
    let mut payload_buffer = vec![0u8; 65535];
    let payload_length = protocol
        .read_message(&message, &mut payload_buffer)
        .expect("Couldn't process message");
    println!("Payload was {:?}", &payload_buffer[..payload_length]);

    // Move to transport mode
    let mut transport_protocol = protocol.into_transport_mode().unwrap();
    let mut payload_buffer = vec![0u8; 65535];
    let message = &connection.receive_data().expect("Could not receive data");
    let payload_length = transport_protocol.read_message(&message, &mut payload_buffer).unwrap();
    println!("{:?}", String::from_utf8_lossy(&payload_buffer[..payload_length]));
}

