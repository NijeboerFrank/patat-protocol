// OP-TEE
use optee_utee::net::TcpStream;
use optee_utee::net::UdpSocket;
use optee_utee::trace_println;
use proto::HASHLEN;

// std
use std::io::{Read, Write};
use std::iter::FromIterator;

// libraries
use merkle_light::hash::Algorithm;
use merkle_light::merkle::MerkleTree;

// TA Code
use crate::evidence::EvidenceProof;
use crate::noise::HandshakeState;
use crate::random::PatatRng;
use crate::x25519::{PublicKey, StaticSecret};

pub struct PatatTA {
    stream: TcpStream,
    handshake_state: HandshakeState,
}

impl PatatTA {
    pub fn connect(ta_secret: StaticSecret, server_pubkey: PublicKey) -> Self {
        // The address of the Host in QEMU is 10.0.2.2
        let mut stream = TcpStream::connect("10.0.2.2", 65432).unwrap();
        trace_println!("Connecting to the server");

        // Handshake start
        let mut handshake_state = HandshakeState::initialize(ta_secret, Some(server_pubkey));
        trace_println!("Handshake started");

        // Message 1
        let payload = handshake_state.write_message_1("test".as_bytes());
        trace_println!("Got payload");
        Self::send_message(&mut stream, &payload);
        trace_println!("Sent 1");

        // Message 2
        let payload = Self::receive_message(&mut stream);
        let decrypted = handshake_state.read_message_2(&payload);
        trace_println!("Received 2");

        // Message 3
        let payload = handshake_state.write_message_3("test".as_bytes());
        Self::send_message(&mut stream, &payload);

        // Send message in transport state
        handshake_state.to_transport_mode();
        let payload = handshake_state.encrypt(b"test");
        Self::send_message(&mut stream, &payload);
        trace_println!("Sent 3");

        trace_println!("Waiting to receive message");
        // Receive in transport state
        let payload = Self::receive_message(&mut stream);
        let decrypted = handshake_state.decrypt(&payload);
        trace_println!("Message \"{}\"", String::from_utf8_lossy(&decrypted));
        PatatTA {
            stream,
            handshake_state,
        }
    }

    pub fn send_evidence(&mut self, evidence: EvidenceProof) {
        let evidence_bytes: Vec<u8> = evidence.into();
        let payload = self.handshake_state.encrypt(&evidence_bytes);
        Self::send_message(&mut self.stream, &payload);
    }

    fn receive_message(stream: &mut TcpStream) -> Vec<u8> {
        let mut receive_buffer = [0u8; 2];
        stream.read_exact(&mut receive_buffer).unwrap();
        let message_length = ((receive_buffer[0] as u32) << 8) + (receive_buffer[1] as u32);
        let mut payload = vec![0u8; message_length as usize];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    fn send_message(stream: &mut TcpStream, payload: &[u8]) {
        let message_length_buffer = [(payload.len() >> 8) as u8, (payload.len() & 0xff) as u8];
        stream.write_all(&message_length_buffer).unwrap();
        stream.write_all(&payload).unwrap();
    }
}
