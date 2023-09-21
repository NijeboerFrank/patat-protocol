use anyhow::Result;
use snow::{Builder, Keypair, TransportState};

use crate::{handshake, patat_connection::PatatConnection, patat_participant::PatatParticipant};

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
        let mut transport = handshake::run_server_handshake(
            builder,
            &self.server_key,
            &connection,
        );
        let message = self.receive_message(&mut transport, &connection).unwrap();
        println!("{:?}", String::from_utf8_lossy(&message));
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
