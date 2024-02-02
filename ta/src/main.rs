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
use proto::Command;

// std
use std::convert::TryInto;

// libraries
use rand_core::RngCore;

// TA Code
use ta::evidence::get_evidence;
use ta::patat_participant::PatatTA;
use ta::random::PatatRng;
use ta::x25519::{PublicKey, StaticSecret};

fn simulate_evidence_fetching(iterations: u32) -> Vec<[u8; 32]> {
    let mut return_value = vec![];
    let mut rng = PatatRng {};

    for _ in 0..iterations {
	let mut data1 = [0u8; 32];
	rng.fill_bytes(&mut data1);

	let version = [0u8; 32];
	let manufacturer_hash = [0u8; 32];
	let hardware_revision = [0u8; 32];
	let file_hash = [0u8; 32];

	let mut iteration = vec![
            data1,
            version,
            manufacturer_hash,
            hardware_revision,
            file_hash,
	];

	return_value.append(&mut iteration);
    }
    return_value
}

fn attest(params: &mut Parameters) {
    let ta_secret = StaticSecret::new(PatatRng);
    let key_bytes: [u8; 32] = "very-secure-password-for-frieten"
        .as_bytes()
        .try_into()
        .unwrap();
    let server_secret = StaticSecret::from(key_bytes);
    let pubkey = PublicKey::from(&server_secret);

    let mut ta = PatatTA::connect(ta_secret, pubkey);

    let evidence = get_evidence(simulate_evidence_fetching(15));
    ta.send_evidence(evidence);
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
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::RunAttested => {
            attest(params);
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
