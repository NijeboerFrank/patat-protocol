use anyhow::Result;
use snow::{Builder, Keypair};

use crate::{handshake, patat_participant::PatatParticipant, patat_connection::PatatConnection};

pub struct Server {
    protocol_builder: Option<Builder<'static>>,
    server_key: Keypair,
}

impl Server {
    pub fn new() -> Self {
        let (protocol_builder, server_key) = Self::setup().unwrap();
        Server {
            protocol_builder: Some(protocol_builder),
            server_key,
        }
    }

    pub fn run_server(mut self) -> Result<()> {
	self.write_keys_to_file()?;
        let connection = PatatConnection::new("127.0.0.1:5071".to_owned(), 5072);

        // Now we can go to the Transport mode since the handshake is done
        let builder = self.protocol_builder.take().unwrap();
        let mut transport =
            handshake::run_server_handshake(builder, &self.server_key, &connection);
        let message = &connection.receive_data().expect("Could not receive data");
        let mut message_buffer = vec![0u8; 65535];
        let payload_length = transport
            .read_message(&message, &mut message_buffer)
            .unwrap();
        println!("{:?}", String::from_utf8_lossy(&message_buffer[..payload_length]));
        let mut message_buf = vec![0u8; 65535];
        let message_len = transport.write_message(b"hello", &mut message_buf).unwrap();
        connection.send_data(&message_buf[..message_len]).unwrap();
        Ok(())
    }
}

impl PatatParticipant for Server {
    fn key_filenames() -> (&'static str, &'static str) {
        ("server.key", "server.key.pub")
    }

    fn keypair(&self) -> &Keypair {
	&self.server_key
    }
}
