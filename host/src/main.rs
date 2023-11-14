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

use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{ParamNone, ParamValue};
use proto::{UUID, Command};
use std::default::Default;

use patat_protocol_rs::{evidence::Evidence, evidence::TestEvidence, evidence::TestVerifierEvidence, combined_evidence::CombinedEvidence, verifier::Verifier};
use rs_merkle::{MerkleProof, algorithms::Sha256};

fn hello_world(session: &mut Session) -> optee_teec::Result<()> {
    let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);

    println!("Invoking command");
    session.invoke_command(Command::RunAttested as u32, &mut operation)?;
    Ok(())
}

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    let relying_party_evidence: TestEvidence = Default::default();
    let verifier_evidence: TestVerifierEvidence = Default::default();

    let mut combined_evidence = CombinedEvidence::new(verifier_evidence.build_root().unwrap(), relying_party_evidence.build_root().unwrap());
    let relying_party_proof = combined_evidence.get_relying_party_proof();
    let verifier_proof = combined_evidence.get_verifier_proof().unwrap();

    let valid = CombinedEvidence::prove_verifier(combined_evidence.get_root(), verifier_proof, verifier_evidence.build_root().unwrap());
    println!("Proof is {:?}", valid);

    hello_world(&mut session)?;

    println!("Success");
    Ok(())
}
