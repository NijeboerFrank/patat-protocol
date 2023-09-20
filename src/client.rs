use anyhow::Result;
use snow::{Builder, Keypair};

use crate::{
    handshake,
    patat_participant::PatatParticipant,
    patat_connection::PatatConnection,
};

pub struct Client {
    protocol_builder: Option<Builder<'static>>,
    client_key: Keypair,
    server_key: Keypair,
}

impl Client {
    pub fn new(server_key: Keypair) -> Self {
        let (protocol_builder, client_key) = Self::setup().unwrap();
        Client {
            protocol_builder: Some(protocol_builder),
            client_key,
	    server_key,
        }
    }

    pub fn run_client(mut self) -> Result<()> {
        self.write_keys_to_file()?;
        let connection = PatatConnection::new("127.0.0.1:5072".to_owned(), 5071);

        // Now we can go to the Transport mode since the handshake is done
        let builder = self.protocol_builder.take().unwrap();
        let mut transport = handshake::run_client_handshake(
            builder,
            &self.client_key,
            &self.server_key,
            &connection,
        );
        let mut message_buf = vec![0u8; 65535];
        let message_len = transport.write_message(b"hello", &mut message_buf).unwrap();
        connection.send_data(&message_buf[..message_len]).unwrap();
        Ok(())
    }
}

impl PatatParticipant for Client {
    fn key_filenames() -> (&'static str, &'static str) {
        ("client.key", "client.key.pub")
    }

    fn keypair(&self) -> &Keypair {
	&self.client_key
    }
}
