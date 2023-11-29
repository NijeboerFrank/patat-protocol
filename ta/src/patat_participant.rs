use crate::x25519::{PublicKey, ReusableSecret, StaticSecret};

use crate::noise::{hmac, CipherState, hash, HandshakeState};
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
    fn new(key: StaticSecret) -> Self {
        Self {
            key
        }
    }
}


