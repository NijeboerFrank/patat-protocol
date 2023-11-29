// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![no_main]

use merkle_light::merkle::MerkleTree;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, HASHLEN};

use crate::x25519::{PublicKey, ReusableSecret};

use crate::noise::{hmac, CipherState, hash, HandshakeState};
use crate::random::PatatRng;

mod hasher;
mod noise;
mod x25519;
mod random;

fn enc_dec() {
    let mut c1 = CipherState::initialize_key(Some([1u8; 32]));
    let mut c2 = CipherState::initialize_key(Some([1u8; 32]));

    let cipher = c1.encrypt_with_ad(&[0u8; 32], "test".as_bytes());
    trace_println!("ciphertext {:?}", &cipher);
    let plain = c2.decrypt_with_ad(&[0u8; 32], &cipher);
    trace_println!("plaintext {:?}", &plain);
}

fn gather_evidence() -> [u8; HASHLEN] {
    use hasher::HashAlgorithm;
    use merkle_light::hash::Algorithm;
    use std::iter::FromIterator;
    use std::hash::Hasher;

    enc_dec();

    let mut h1 = [0u8; HASHLEN];
    let mut h2 = [0u8; HASHLEN];
    let mut h3 = [0u8; HASHLEN];
    h1[0] = 0x11;
    h2[0] = 0x22;
    h3[0] = 0x33;

    let mut hasher = HashAlgorithm::new();
    hasher.write("test".as_bytes());
    trace_println!("[+] hash {:?}", hasher.hash());

    trace_println!("[+] other hash {:?}", hash("test".as_bytes()));

    let pass = "testtesttesttesttesttesttesttest".as_bytes();
    let mut pass_buffer: [u8; 32] = [0u8; 32];
    pass_buffer.clone_from_slice(&pass);

    trace_println!("[+] hmac {:?}", hmac(&pass_buffer, "test".as_bytes()));

    let tree: MerkleTree<[u8; HASHLEN], HashAlgorithm> = MerkleTree::from_iter(vec![h1, h2, h3]);
    trace_println!("[+] {:?}", tree.root());

    let mut h1 = [0u8; HASHLEN];
    h1
}

fn attest() {
    trace_println!("[+] TA Attest");
    let mut ta_secret = ReusableSecret::new(PatatRng);
    let mut server_secret = ReusableSecret::new(PatatRng);
    let mut pubkey = PublicKey::from(&server_secret);
    trace_println!("State");

    let handshake_state = HandshakeState::initialize(ta_secret, pubkey);
    trace_println!("done");
    gather_evidence();
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, _params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::RunAttested => {
            attest();
            Ok(())
        }
        Command::RunWithoutAttestation => Ok(()),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"Patat-Protocol Implemented in OP-TEE \0";
const EXT_PROP_VALUE_1: &[u8] = b"Patat-Protocol TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
