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

use optee_teec::{Context, Operation, ParamTmpRef, ParamType, Session, Uuid};
use optee_teec::{ParamNone, ParamValue};
use proto::{Command, UUID};
use std::default::Default;
use std::time::Instant;

/// Run the Proof of Concept TEE.
///
/// In the TEE, attest the application to an attestation server.
fn run_tee(session: &mut Session) -> optee_teec::Result<()> {
    let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
    session.invoke_command(Command::RunWithoutAttestation as u32, &mut operation)?;
    Ok(())
}

/// The main run method
fn run() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    for _ in 0..1000 {
        let now = Instant::now();
        run_tee(&mut session)?;
        let elapsed = now.elapsed();
        println!("Elapsed: {} ms", elapsed.as_millis());
    }

    println!("Done");
    Ok(())
}

fn main() -> optee_teec::Result<()> {
    run()
}
