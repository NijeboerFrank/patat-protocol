use snow::{Builder, TransportState, Keypair};

use crate::patat_connection::PatatConnection;

pub fn run_client_handshake(
    protocol_builder: Builder,
    client_keypair: &Keypair,
    server_keypair: &Keypair,
    connection: &PatatConnection,
) -> TransportState {
    let mut handshake_state = protocol_builder
        .local_private_key(&client_keypair.private)
        .remote_public_key(&server_keypair.public)
        .build_initiator()
        .expect("Could not start protocol");

    // -> e, es
    let mut buf = vec![0u8; 65535];
    let message_len = handshake_state.write_message(&[0], &mut buf).unwrap();
    connection.send_data(&buf[..message_len]).unwrap();

    // <- e, ee
    let message = connection.receive_data().unwrap();
    let mut payload_buffer = vec![0u8; 65535];
    let payload_length = handshake_state
        .read_message(&message, &mut payload_buffer)
        .unwrap();
    println!("Payload was {:?}", &payload_buffer[..payload_length]);

    // -> s, se
    let mut buf = vec![0u8; 65535];
    let message_len = handshake_state.write_message(&[2], &mut buf).unwrap();
    connection.send_data(&buf[..message_len]).unwrap();

    // Now we can go to the Transport mode since the handshake is done
    handshake_state.into_transport_mode().unwrap()
}

pub fn run_server_handshake(
    protocol_builder: Builder,
    server_keypair: &Keypair,
    connection: &PatatConnection,
) -> TransportState {
    // Setup the handshake protocol
    let mut protocol = protocol_builder
        .local_private_key(&server_keypair.private)
        .build_responder()
        .expect("Could not start protocol");

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
    protocol.into_transport_mode().unwrap()
}
