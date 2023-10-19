use anyhow::Result;
use snow::{Builder, Keypair, TransportState};

use crate::{
    combined_evidence::CombinedEvidence, patat_connection::PatatConnection,
    patat_participant::PatatParticipant,
};

pub struct Server {
    protocol_builder: Option<Builder<'static>>,
    server_keypair: Keypair,
}

impl Server {
    pub fn new() -> Self {
        let (protocol_builder, server_keypair) = Self::setup().unwrap();
        Server {
            protocol_builder: Some(protocol_builder),
            server_keypair,
        }
    }

    pub fn run_server(mut self) -> Result<()> {
        self.write_keys_to_file()?;
        let connection = PatatConnection::new("127.0.0.1:5071".to_owned(), 5072);

        // Now we can go to the Transport mode since the handshake is done
        let mut transport = self.run_handshake(&connection);
        let message = self.receive_message(&mut transport, &connection).unwrap();
        println!("{:?}", String::from_utf8_lossy(&message));
        self.transfer_message(b"hello", &mut transport, &connection)
            .unwrap();

        let merkle_proof = self.receive_message(&mut transport, &connection).unwrap();

        // let evidence1: TestEvidence = Default::default();
        // let evidence2: TestEvidence = Default::default();
        let mut evidence_tree = CombinedEvidence::new();

        let valid = evidence_tree.prove_subtree(merkle_proof).unwrap();

        println!("Merkle proof is {}", valid);
        Ok(())
    }

    fn run_handshake(&mut self, connection: &PatatConnection) -> TransportState {
        // Setup the handshake protocol
        let mut protocol = self
            .protocol_builder
            .take()
            .unwrap()
            .local_private_key(&self.server_keypair.private)
            .build_responder()
            .expect("Could not start protocol");

        // -> e, es
        let message = &connection.receive_data().expect("Could not receive data");
        let mut payload_buffer = vec![0u8; 65535];
        let _payload_length = protocol
            .read_message(message, &mut payload_buffer)
            .expect("Couldn't process message");

        // <- e, ee
        let mut buf = vec![0u8; 65535];
        let message_len = protocol
            .write_message(&[1], &mut buf)
            .expect("Something went wrong with creating a new message");
        connection.send_data(&buf[..message_len]).unwrap();

        // -> s, se
        let message = &connection.receive_data().expect("Could not receive data");
        let mut payload_buffer = vec![0u8; 65535];
        let _payload_length = protocol
            .read_message(message, &mut payload_buffer)
            .expect("Couldn't process message");

        // Move to transport mode
        protocol.into_transport_mode().unwrap()
    }
}

impl PatatParticipant for Server {
    fn key_filenames() -> (&'static str, &'static str) {
        ("server.key", "server.key.pub")
    }

    fn keypair(&self) -> &Keypair {
        &self.server_keypair
    }
}
