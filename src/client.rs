use anyhow::Result;
use snow::TransportState;
use snow::{Builder, Keypair};

use crate::merkle_tree;
use crate::{patat_connection::PatatConnection, patat_participant::PatatParticipant};

pub struct Client {
    protocol_builder: Option<Builder<'static>>,
    client_keypair: Keypair,
    server_keypair: Keypair,
}

impl Client {
    pub fn new(server_keypair: Keypair) -> Self {
        let (protocol_builder, client_keypair) = Self::setup().unwrap();
        Client {
            protocol_builder: Some(protocol_builder),
            client_keypair,
            server_keypair,
        }
    }

    pub fn run_client(mut self) -> Result<()> {
        self.write_keys_to_file()?;
        let connection = PatatConnection::new("127.0.0.1:5072".to_owned(), 5071);

        // Now we can go to the Transport mode since the handshake is done
        let mut transport = self.run_handshake(&connection);

        self.transfer_message(b"hello", &mut transport, &connection)
            .unwrap();
        let message = self.receive_message(&mut transport, &connection).unwrap();
        println!("{:?}", String::from_utf8_lossy(&message));

	let (merkle_root, merkle_proof) = merkle_tree::build_evidence().unwrap();

	self.transfer_message(&merkle_root, &mut transport, &connection).unwrap();
	self.transfer_message(&merkle_proof, &mut transport, &connection).unwrap();
        Ok(())
    }

    fn run_handshake(&mut self, connection: &PatatConnection) -> TransportState {
        let mut handshake_state = self
            .protocol_builder
            .take()
            .unwrap()
            .local_private_key(&self.client_keypair.private)
            .remote_public_key(&self.server_keypair.public)
            .build_initiator()
            .expect("Could not start protocol");

        // -> e, es
        let mut buf = vec![0u8; 65535];
        let message_len = handshake_state.write_message(&[0], &mut buf).unwrap();
        connection.send_data(&buf[..message_len]).unwrap();

        // <- e, ee
        let message = connection.receive_data().unwrap();
        let mut payload_buffer = vec![0u8; 65535];
        let _payload_length = handshake_state
            .read_message(&message, &mut payload_buffer)
            .unwrap();

        // -> s, se
        let mut buf = vec![0u8; 65535];
        let message_len = handshake_state.write_message(&[2], &mut buf).unwrap();
        connection.send_data(&buf[..message_len]).unwrap();

        // Now we can go to the Transport mode since the handshake is done
        handshake_state.into_transport_mode().unwrap()
    }
}

impl PatatParticipant for Client {
    fn key_filenames() -> (&'static str, &'static str) {
        ("client.key", "client.key.pub")
    }

    fn keypair(&self) -> &Keypair {
        &self.client_keypair
    }
}
