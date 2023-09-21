use anyhow::Result;
use snow::{Builder, Keypair, TransportState};

use crate::{
    handshake,
    patat_participant::PatatParticipant,
    patat_connection::PatatConnection,
};

pub struct Client {
    protocol_builder: Option<Builder<'static>>,
    transport: Option<TransportState>,
    connection: Option<PatatConnection>,
    client_key: Keypair,
    server_key: Keypair,
}

impl Client {
    pub fn new(server_key: Keypair) -> Self {
        let (protocol_builder, client_key) = Self::setup().unwrap();
        Client {
            protocol_builder: Some(protocol_builder),
	    transport: None,
	    connection: None,
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

	self.transfer_message(b"hello", &mut transport, &connection).unwrap();
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
