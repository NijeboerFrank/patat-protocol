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

use optee_teec::{Context, Operation, ParamType, ParamTmpRef, Session, Uuid};
use optee_teec::{ParamNone, ParamValue};
use proto::{UUID, Command};
use std::default::Default;
use std::time::Instant;

fn run_tee(session: &mut Session) -> optee_teec::Result<()> {
    let mut file_hash = ParamTmpRef::new_input(&[0u8; 32]); 
    let mut version_id = ParamTmpRef::new_input(&[0u8; 32]); 
    let mut manufacturer_hash = ParamTmpRef::new_input(&[0u8; 32]); 

    let mut operation = Operation::new(0, file_hash, version_id, manufacturer_hash, ParamNone);

    println!("Invoking command");
    session.invoke_command(Command::RunAttested as u32, &mut operation)?;
    Ok(())
}

fn run() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    let now = Instant::now();

    run_tee(&mut session)?;

    let elapsed = now.elapsed();
    println!("Elapsed: {} ms", elapsed.as_millis());

    println!("Success");
    Ok(())
}

fn main() -> optee_teec::Result<()> {
    run()
}
