use optee_utee::{
    trace_println, AlgorithmId, AttributeId, AttributeMemref, Mac, TransientObject,
    TransientObjectType,
};

use proto::{DHLEN, HASHLEN};

use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::hash::Hasher;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use merkle_light::hash::Algorithm;

use crate::hasher::HashAlgorithm;
use crate::random::PatatRng;
use crate::x25519::{PublicKey, ReusableSecret, StaticSecret};

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
                }
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
        Self { k, n }
    }

    // pub fn has_key(&self) -> bool {
    //     self.k.is_some()
    // }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
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
            }
            None => {
                let mut ret = vec![0u8; plaintext.len()];
                ret.clone_from_slice(plaintext);
                self.n += 1;
                ret
            }
        }
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
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
            }
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

    // pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
    //     self.h
    // }

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

    pub fn split(&self) -> (CipherState, CipherState) {
        let (temp_k1, temp_k2) = self.hkdf_2(&[]);
        (
            CipherState::initialize_key(Some(temp_k1)),
            CipherState::initialize_key(Some(temp_k2)),
        )
    }
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: StaticSecret,
    e: Option<ReusableSecret>,
    rs: Option<PublicKey>,
    re: Option<PublicKey>,
    transport_mode_states: Option<(CipherState, CipherState)>,
}

impl HandshakeState {
    pub fn initialize(s: StaticSecret, rs: Option<PublicKey>) -> Self {
        let mut symmetric_state =
            SymmetricState::initialize_symmetric("Noise_XK_25519_ChaChaPoly_SHA256");

        // MixHash(prologue)
        symmetric_state.mix_hash(&[0u8; 0]);
        // MixHash(rs) -> pre-messages
        match rs {
            Some(rs) => symmetric_state.mix_hash(rs.as_bytes()),
            None => {
                let s_pub = PublicKey::from(&s);
                symmetric_state.mix_hash(s_pub.as_bytes());
            }
        };

        HandshakeState {
            symmetric_state,
            s,
            e: None,
            rs,
            re: None,
            transport_mode_states: None,
        }
    }

    /// -> e, es
    pub fn write_message_1(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // e
        let e = ReusableSecret::new(PatatRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);
        let e_pub_bytes = e_pub.to_bytes();
        self.symmetric_state.mix_hash(&e_pub_bytes);
        payload_buffer.extend_from_slice(&e_pub_bytes);

        // es
        self.symmetric_state.mix_key(
            self.e
                .as_ref()
                .unwrap()
                .diffie_hellman(&self.rs.unwrap())
                .as_bytes(),
        );

        // encrypt payload
        let ciphertext = self.symmetric_state.encrypt_and_hash(payload);
        payload_buffer.extend_from_slice(&ciphertext);

        payload_buffer
    }

    /// -> e, es
    /// But now from the responder's side
    pub fn read_message_1(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // e
        let re_bytes: [u8; 32] = payload[0..DHLEN].try_into().unwrap();
        let re: PublicKey = re_bytes.into();
        self.symmetric_state.mix_hash(re.as_bytes());
        self.re = Some(re);

        // es
        self.symmetric_state
            .mix_key(self.s.diffie_hellman(&self.re.unwrap()).as_bytes());

        // decrypt payload
        let plaintext = self.symmetric_state.decrypt_and_hash(&payload[DHLEN..]);
        payload_buffer.extend_from_slice(&plaintext);

        payload_buffer
    }

    /// <- e, ee
    pub fn write_message_2(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // e
        let e = ReusableSecret::new(PatatRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);
        let e_pub_bytes = e_pub.to_bytes();
        self.symmetric_state.mix_hash(&e_pub_bytes);
        payload_buffer.extend_from_slice(&e_pub_bytes);

        // ee
        self.symmetric_state.mix_key(
            self.e
                .as_ref()
                .unwrap()
                .diffie_hellman(&self.re.unwrap())
                .as_bytes(),
        );

        // encrypt payload
        let ciphertext = self.symmetric_state.encrypt_and_hash(payload);
        payload_buffer.extend_from_slice(&ciphertext);

        payload_buffer
    }

    pub fn read_message_2(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // e
        let re_bytes: [u8; 32] = payload[0..DHLEN].try_into().unwrap();
        let re: PublicKey = re_bytes.into();
        self.symmetric_state.mix_hash(re.as_bytes());
        self.re = Some(re);

        // ee
        self.symmetric_state.mix_key(
            self.e
                .as_ref()
                .unwrap()
                .diffie_hellman(&self.re.unwrap())
                .as_bytes(),
        );

        // decrypt payload
        let plaintext = self.symmetric_state.decrypt_and_hash(&payload[DHLEN..]);
        payload_buffer.extend_from_slice(&plaintext);

        payload_buffer
    }

    /// -> s, se
    pub fn write_message_3(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // s
        let s_pub = PublicKey::from(&self.s);
        let encrypted_key = self.symmetric_state.encrypt_and_hash(s_pub.as_bytes());
        payload_buffer.extend_from_slice(&encrypted_key);

        // se
        self.symmetric_state
            .mix_key(self.s.diffie_hellman(&self.re.unwrap()).as_bytes());

        // encrypt payload
        let ciphertext = self.symmetric_state.encrypt_and_hash(payload);
        payload_buffer.extend_from_slice(&ciphertext);

        payload_buffer
    }

    pub fn read_message_3(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut payload_buffer = vec![];

        // s
        let rs_bytes: [u8; 32] = self
            .symmetric_state
            .decrypt_and_hash(&payload[0..DHLEN + 16])
            .try_into()
            .unwrap();
        let rs: PublicKey = rs_bytes.into();
        self.rs = Some(rs);

        // se
        self.symmetric_state.mix_key(
            self.e
                .as_ref()
                .unwrap()
                .diffie_hellman(&self.rs.unwrap())
                .as_bytes(),
        );

        // decrypt payload
        let plaintext = self
            .symmetric_state
            .decrypt_and_hash(&payload[DHLEN + 16..]);
        payload_buffer.extend_from_slice(&plaintext);

        payload_buffer
    }

    pub fn to_transport_mode(&mut self) {
        self.transport_mode_states = Some(self.symmetric_state.split());
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        if self.transport_mode_states.is_none() {
            panic!()
        }
        let mut ts = self.transport_mode_states.take();
        let ret = ts.as_mut().unwrap().0.encrypt_with_ad(&[], payload);
        self.transport_mode_states = ts;
        ret
    }

    pub fn decrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        if self.transport_mode_states.is_none() {
            panic!()
        }
        let mut ts = self.transport_mode_states.take();
        let ret = ts.as_mut().unwrap().1.decrypt_with_ad(&[], payload);
        self.transport_mode_states = ts;
        ret
    }
}
