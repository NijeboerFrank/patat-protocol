use crate::x25519::{EphemeralSecret, PublicKey, ReusableSecret};
use optee_utee::{trace_println, Error, ErrorKind, Parameters, Result};
use optee_utee::{AlgorithmId, DeriveKey, Digest};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use proto::{BASE, KEY_SIZE, PRIME};

pub struct DiffieHellman {
    pub key: TransientObject,
}

impl DiffieHellman {
    /// Generate a fresh DH Key
    pub fn new() -> Self {
        let attr_prime = AttributeMemref::from_ref(AttributeId::DhPrime, &PRIME);
        let attr_base = AttributeMemref::from_ref(AttributeId::DhBase, &BASE);

        let mut dh = DiffieHellman {
            key: TransientObject::allocate(TransientObjectType::DhKeypair, KEY_SIZE).unwrap(),
        };

        dh.key
            .generate_key(KEY_SIZE, &[attr_prime.into(), attr_base.into()])
            .expect("Could not generate key");

        let mut public_buffer = [0u8; 256];
        let mut private_buffer = [0u8; 256];

        let mut key_size_public = dh
            .key
            .ref_attribute(AttributeId::DhPublicValue, &mut public_buffer)
            .unwrap();
        let mut key_size_private = dh
            .key
            .ref_attribute(AttributeId::DhPrivateValue, &mut private_buffer)
            .unwrap();

        dh
    }
}

pub struct CipherState {
    k: [u8; 32],
    n: [u8; 8],
}

pub struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
}

pub struct HandshakeState {
    s: ReusableSecret,
    e: EphemeralSecret,
    rs: PublicKey,
    re: PublicKey,
}
