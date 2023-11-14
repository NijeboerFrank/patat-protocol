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
use proto::Command;

mod hasher {
    use merkle_light::hash::{Algorithm, Hashable};
    use optee_utee::{AlgorithmId, Digest};
    use std::default::Default;
    use std::hash::Hasher;
    use optee_utee::trace_println;

    pub struct HashAlgorithm {
        pub op: Digest,
    }

    impl HashAlgorithm {
        pub fn new() -> HashAlgorithm {
            HashAlgorithm {
                op: Digest::allocate(AlgorithmId::Sha256).unwrap(),
            }
        }
    }

    impl Hasher for HashAlgorithm {
        #[inline]
        fn write(&mut self, msg: &[u8]) {
            trace_println!("[++] Write called");
            self.op.update(msg);
        }

        #[inline]
        fn finish(&self) -> u64 {
            trace_println!("[++] Finish called");
            let mut hash = [0u8; 32];
            let length = self.op.do_final(&[], &mut hash).unwrap();
            let h = &hash[..length];
            trace_println!("{:?}", h);
            0
        }
    }

    impl Default for HashAlgorithm {
        fn default() -> HashAlgorithm {
            HashAlgorithm::new()
        }
    }

    impl Algorithm<[u8; 32]> for HashAlgorithm {
        #[inline]
        fn hash(&mut self) -> [u8; 32] {
            trace_println!("[++] Hash called");
            let mut h = [0u8; 32];
            self.op.do_final(&[], &mut h);
            h
        }

        #[inline]
        fn reset(&mut self) {
            trace_println!("[++] Reset called");
            self.op = Digest::allocate(AlgorithmId::Sha256).unwrap();
        }
    }
}

fn gather_evidence() -> [u8; 32] {
    use hasher::HashAlgorithm;
    use std::iter::FromIterator;

    let mut h1 = [0u8; 32];
    let mut h2 = [0u8; 32];
    let mut h3 = [0u8; 32];
    h1[0] = 0x11;
    h2[0] = 0x22;
    h3[0] = 0x33;

    let tree: MerkleTree<[u8; 32], HashAlgorithm> = MerkleTree::from_iter(vec![h1, h2, h3]);
    trace_println!("[+] {:?}", tree.root());

    let mut h1 = [0u8; 32];
    h1
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

fn attest() {
    trace_println!("[+] TA Attest");
    gather_evidence();
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
