use optee_utee::net::TcpStream;
use optee_utee::net::UdpSocket;
use optee_utee::trace_println;

use std::io::{Read, Write};

use crate::noise::HandshakeState;
use crate::random::PatatRng;
use crate::x25519::{PublicKey, StaticSecret};

pub struct PatatTA {}

pub struct PatatRelyingParty {}

impl PatatTA {
    pub fn connect(ta_secret: StaticSecret, server_pubkey: PublicKey) -> Self {
        // The address of the Host in QEMU is 10.0.2.2
        let mut stream = TcpStream::connect("10.0.2.2", 65432).unwrap();

        // Handshake start
        let mut handshake_state = HandshakeState::initialize(ta_secret, Some(server_pubkey));

        // Message 1
        let payload = handshake_state.write_message_1("test".as_bytes());
        let message_length_buffer = [(payload.len() >> 8) as u8, (payload.len() & 0xff) as u8];
        stream.write_all(&message_length_buffer).unwrap();
        stream.write_all(&payload).unwrap();

        // Message 2
        let mut receive_buffer = [0u8; 2];
        stream.read_exact(&mut receive_buffer).unwrap();
        let message_length = ((receive_buffer[0] as u32) << 8) + (receive_buffer[1] as u32);
        let mut payload = vec![0u8; message_length as usize];
        stream.read_exact(&mut payload).unwrap();
        let decrypted = handshake_state.read_message_2(&payload);

        // Message 3
        let payload = handshake_state.write_message_3("test".as_bytes());
        let message_length_buffer = [(payload.len() >> 8) as u8, (payload.len() & 0xff) as u8];
        stream.write_all(&message_length_buffer).unwrap();
        stream.write_all(&payload).unwrap();

        handshake_state.to_transport_mode();
        let payload = handshake_state.encrypt(b"test");
        let message_length_buffer = [(payload.len() >> 8) as u8, (payload.len() & 0xff) as u8];
        stream.write_all(&message_length_buffer).unwrap();
        stream.write_all(&payload).unwrap();
        PatatTA {}
    }
}
