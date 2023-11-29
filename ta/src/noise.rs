use std::hash::Hasher;
use optee_utee::{trace_println, Error, ErrorKind, Parameters, Result};
use optee_utee::{AlgorithmId, AttributeId, AttributeMemref, DeriveKey, Digest, Mac, TransientObject, TransientObjectType};
use std::ptr;
use proto::{BASE, KEY_SIZE, PRIME, HASHLEN};
use merkle_light::hash::Algorithm;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead, Payload};

use crate::x25519::{EphemeralSecret, PublicKey, ReusableSecret};
use crate::hasher::HashAlgorithm;
use crate::random::PatatRng;

pub fn hmac(key: &[u8; HASHLEN], data: &[u8]) -> [u8; HASHLEN] {
    let mut out = [0u8; HASHLEN];
    
    match Mac::allocate(AlgorithmId::HmacSha256, HASHLEN * 8) {
        Err(e) => panic!(e),
        Ok(mac) => {
            match TransientObject::allocate(TransientObjectType::HmacSha256, key.len() * 8) {
                Err(e) => panic!(e),
                Ok(mut key_object) => {
                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, key);
                    key_object.populate(&[attr.into()]).unwrap();
                    mac.set_key(&key_object).unwrap();
                },
            };
            mac.init(&[0u8; 0]);
            mac.compute_final(&data, &mut out).unwrap();
        }
    };
    out
}

pub fn hash(data: &[u8]) -> [u8; HASHLEN] {
    let mut hasher = HashAlgorithm::new();
    hasher.write(data);
    hasher.hash()
}

pub struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {

    pub fn initialize_key(key: Option<[u8; 32]>) -> Self {
        let k = key;
        let n = 0;
        Self {
            k,
            n,
        }
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8; HASHLEN], plaintext: &[u8]) -> Vec<u8> {
        match self.k {
            Some(k) => {
                let key = Key::from_slice(&k);
                let cipher = ChaCha20Poly1305::new(&key);
                let nonce = &self.n.to_le_bytes();

                // Bit awkward, but must do it, because chacha needs to nonce to be 12 bits
                let mut nonce_slice = [0u8; 12];
                nonce_slice[4..].clone_from_slice(nonce);
                let nonce = Nonce::from_slice(&nonce_slice);
                let payload = Payload {
                    msg: plaintext,
                    aad: ad,
                };
                let ciphertext = cipher.encrypt(&nonce, payload).unwrap();
                self.n += 1;
                ciphertext
            },
            None => {
                let mut ret = vec![0u8; plaintext.len()];
                ret.clone_from_slice(plaintext);
                self.n += 1;
                ret
            }
        }
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8; HASHLEN], ciphertext: &[u8]) -> Vec<u8> {
        match self.k {
            Some(k) => {
                let key = Key::from_slice(&k);
                let cipher = ChaCha20Poly1305::new(&key);

                // Bit awkward, but must do it, because chacha needs to nonce to be 12 bits
                let nonce = &self.n.to_le_bytes();
                let mut nonce_slice = [0u8; 12];
                nonce_slice[4..].clone_from_slice(nonce);
                let nonce = Nonce::from_slice(&nonce_slice);

                let payload = Payload {
                    msg: ciphertext,
                    aad: ad,
                };
                let plaintext = cipher.decrypt(&nonce, payload).unwrap();
                self.n += 1;
                plaintext
            },
            None => {
                let mut ret = vec![];
                ret.extend_from_slice(ciphertext);
                self.n += 1;
                ret
            }
        }
    }
}

pub struct SymmetricState {
    cipher_state: CipherState,
    ck: [u8; 32],
    h: [u8; HASHLEN],
}

impl SymmetricState {
    pub fn initialize_symmetric(protocol_name: &str) -> Self {
        let mut h = [0u8; HASHLEN];
        let name_bytes = protocol_name.as_bytes();
        h[0..name_bytes.len()].copy_from_slice(name_bytes);
        let mut ck = [0u8; HASHLEN];
        ck.copy_from_slice(&h);
        let cipher_state = CipherState::initialize_key(None);
        Self {
            cipher_state,
            ck,
            h,
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k) = self.hkdf_2(input_key_material);
        self.ck = ck;
        self.cipher_state = CipherState::initialize_key(Some(temp_k));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut concatenation = vec![];
        concatenation.extend_from_slice(&self.h);
        concatenation.extend_from_slice(data);
        self.h = hash(&concatenation);
    }

    pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
        self.h
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self.cipher_state.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let plaintext = self.cipher_state.decrypt_with_ad(&self.h, ciphertext);
        self.mix_hash(&ciphertext);
        plaintext
    }

    fn hkdf_2(&self, input_key_material: &[u8]) -> ([u8; HASHLEN], [u8; HASHLEN]) {
        let temp_key = hmac(&self.ck, input_key_material);
        let output1 = hmac(&temp_key, &[0x01]);

        let mut next_input = vec![0x02; HASHLEN + 1];
        next_input[..HASHLEN].copy_from_slice(&output1);
        let output2 = hmac(&temp_key, &next_input);

        (output1, output2)
    }

    fn hkdf_3(&self, input_key_material: &[u8]) -> ([u8; HASHLEN], [u8; HASHLEN], [u8; HASHLEN]) {
        let temp_key = hmac(&self.ck, input_key_material);
        let output1 = hmac(&temp_key, &[0x01]);

        let mut next_input = vec![0x02; HASHLEN + 1];
        next_input[..HASHLEN].copy_from_slice(&output1);
        let output2 = hmac(&temp_key, &next_input);

        let mut next_input = vec![0x03; HASHLEN + 1];
        next_input[..HASHLEN].copy_from_slice(&output2);
        let output3 = hmac(&temp_key, &next_input);

        (output1, output2, output3)
    }
    
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: ReusableSecret,
    e: Option<EphemeralSecret>,
    rs: PublicKey,
    re: Option<PublicKey>,
}



impl HandshakeState {

    pub fn initialize(s: ReusableSecret, rs: PublicKey) -> Self {
        let mut state = HandshakeState {
            symmetric_state: SymmetricState::initialize_symmetric("PATAT_PROTOCOL"),
            s,
            e: None,
            rs,
            re: None,
        };
        // MixHash(prologue)
        state.symmetric_state.mix_hash("v0.0.1".as_bytes());
        // MixHash(rs) -> pre-messages
        state.symmetric_state.mix_hash(rs.as_bytes());
        state
    }

    pub fn write_message_1(&mut self, payload: &[u8], message_buffer: &mut [u8]) -> usize {
        let e = EphemeralSecret::new(PatatRng);
        let e_pub = PublicKey::from(&e);
        let e_pub_bytes = e_pub.to_bytes();

        if e_pub_bytes.len() > message_buffer.len() {
            panic!("error");
        }

        self.symmetric_state.mix_hash(&e_pub_bytes);

        e_pub_bytes.len()

    }

    

   // pub fn write_message(&self, payload: &[u8], message_buffer: )
}
