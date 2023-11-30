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

// OP-TEE
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, HASHLEN};

// std
use std::convert::TryInto;
use std::hash::Hasher;
use std::iter::FromIterator;

// libraries
use merkle_light::hash::Algorithm;
use merkle_light::merkle::MerkleTree;

// TA Code
use ta::hasher::HashAlgorithm;
use ta::noise::HandshakeState;
use ta::patat_participant::PatatTA;
use ta::random::PatatRng;
use ta::x25519::{PublicKey, StaticSecret};

fn gather_evidence() -> [u8; HASHLEN] {
    let mut h1 = [0u8; HASHLEN];
    let mut h2 = [0u8; HASHLEN];
    let mut h3 = [0u8; HASHLEN];
    h1[0] = 0x11;
    h2[0] = 0x22;
    h3[0] = 0x33;

    let tree: MerkleTree<[u8; HASHLEN], HashAlgorithm> = MerkleTree::from_iter(vec![h1, h2, h3]);
    trace_println!("[+] {:?}", tree.root());

    let h1 = [0u8; HASHLEN];
    h1
}

fn attest() {
    // trace_println!("[+] TA Attest");
    // let ta_secret = StaticSecret::new(PatatRng);
    // let server_secret = StaticSecret::new(PatatRng);
    // let pubkey = PublicKey::from(&server_secret);
    // trace_println!("State");

    // let mut handshake_state = HandshakeState::initialize(ta_secret, Some(pubkey));
    // let mut handshake_state_receiver = HandshakeState::initialize(server_secret, None);
    // let payload = handshake_state.write_message_1("test".as_bytes());
    // let decrypted = handshake_state_receiver.read_message_1(&payload);
    // trace_println!("done");
    // trace_println!("payload {:?}", &payload);
    // trace_println!("decrypted payload {:?}", &decrypted);

    // let payload = handshake_state_receiver.write_message_2("test".as_bytes());
    // let decrypted = handshake_state.read_message_2(&payload);
    // trace_println!("done again");
    // trace_println!("payload {:?}", &payload);
    // trace_println!("decrypted payload {:?}", &decrypted);

    // let payload = handshake_state_receiver.write_message_3("test".as_bytes());
    // let decrypted = handshake_state.read_message_3(&payload);
    // trace_println!("done again");
    // trace_println!("payload {:?}", &payload);
    // trace_println!("decrypted payload {:?}", &decrypted);
    // gather_evidence();

    let ta_secret = StaticSecret::new(PatatRng);
    let key_bytes: [u8; 32] = "very-secure-password-for-frieten"
        .as_bytes()
        .try_into()
        .unwrap();
    let server_secret = StaticSecret::from(key_bytes);
    let pubkey = PublicKey::from(&server_secret);
    PatatTA::connect(ta_secret, pubkey);
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
