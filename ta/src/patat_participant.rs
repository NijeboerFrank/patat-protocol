use optee_utee::net::UdpSocket;
use optee_utee::net::TcpStream;

use std::io::{Read, Write};

use crate::x25519::{PublicKey, StaticSecret};
use crate::noise::HandshakeState;
use crate::random::PatatRng;


pub struct PatatTA {
    key: StaticSecret,
    rp_pub: PublicKey,
}

impl PatatTA {
    fn new(key: StaticSecret, rp_pub: PublicKey) -> Self {
        Self {
            key,
            rp_pub,
        }
    }
}

pub struct PatatRelyingParty {
    key: StaticSecret,
}


impl PatatRelyingParty {
    pub fn new(key: StaticSecret) -> Self {
        Self {
            key
        }
    }

    pub fn connect(&self) {
        let mut stream = TcpStream::connect("Tatooine", 65432).unwrap();
        stream.write_all(b"[TA] Hello!").unwrap();
    }
}


