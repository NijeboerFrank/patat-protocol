use snow::{Builder, Keypair};

use crate::patat_connection::PatatConnection;

pub fn run_client(
    protocol_builder: Builder,
    keys: Keypair,
    server_static_key: Vec<u8>,
) -> std::io::Result<()> {
    let client_static_key = keys.private;
    let mut protocol = protocol_builder
        .local_private_key(&client_static_key)
        .remote_public_key(&server_static_key)
        .build_initiator()
        .expect("Could not start protocol");

    let connection = PatatConnection::new("127.0.0.1:5072".to_owned(), 5071);

    // -> e, es
    let mut buf = vec![0u8; 65535];
    let message_len = protocol.write_message(&[0], &mut buf).unwrap();
    connection.send_data(&buf[..message_len])?;

    // <- e, ee
    let message = connection.receive_data().unwrap();
    let mut payload_buffer = vec![0u8; 65535];
    let payload_length = protocol.read_message(&message, &mut payload_buffer).unwrap();
    println!("Payload was {:?}", &payload_buffer[..payload_length]);

    // -> s, se
    let mut buf = vec![0u8; 65535];
    let message_len = protocol.write_message(&[2], &mut buf).unwrap();
    connection.send_data(&buf[..message_len])?;

    // Now we can go to the Transport mode since the handshake is done
    let mut transport = protocol.into_transport_mode().unwrap();
    let mut message_buf = vec![0u8; 65535];
    let message_len = transport.write_message(b"hello", &mut message_buf).unwrap();
    connection.send_data(&message_buf[..message_len]).unwrap();

    Ok(())
}
