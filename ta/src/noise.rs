use optee_utee::{AlgorithmId, DeriveKey, Digest};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result, trace_println};
use proto::{PRIME, BASE, KEY_SIZE};
use crate::x25519::{EphemeralSecret, PublicKey};

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

        dh.key.generate_key(KEY_SIZE, &[attr_prime.into(), attr_base.into()]).expect("Could not generate key");

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
