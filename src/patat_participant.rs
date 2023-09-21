use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;
use snow::params::NoiseParams;
use snow::{Builder, Keypair, TransportState};

use crate::patat_connection::PatatConnection;

pub trait PatatParticipant {
    fn setup() -> Result<(Builder<'static>, Keypair), &'static str> {
        let params: NoiseParams = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let builder = Builder::new(params);

        let keypair = match Self::read_keys_from_file() {
            Some(keypair) => keypair,
            None => builder
                .generate_keypair()
                .expect("Could not generate client keypair"),
        };
        Ok((builder, keypair))
    }

    fn key_filenames() -> (&'static str, &'static str);

    fn keypair(&self) -> &Keypair;

    fn transfer_message(&self, message: &[u8], transport: &mut TransportState, connection: &PatatConnection) -> Result<()> {
	let mut message_buf = vec![0u8; 65535];
        let message_len = transport.write_message(message, &mut message_buf).unwrap();
        connection.send_data(&message_buf[..message_len]).unwrap();
	Ok(())
    }

    fn receive_message(&self, transport: &mut TransportState, connection: &PatatConnection) -> Result<Vec<u8>> {
	let mut message_buf = vec![0u8; 65535];
        let response = connection.receive_data()?;
	let message_length = transport.read_message(&response, &mut message_buf)?;
	let response = &message_buf[..message_length];
	Ok(response.to_vec())
    }

    fn read_keys_from_file() -> Option<Keypair> {
        let (private_key_file, public_key_file) = Self::key_filenames();
        let path = Path::new(private_key_file);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => return None,
        };

        let mut private = vec!();
        if file.read_to_end(&mut private).is_err() {
            return None;
        }

        let path = Path::new(public_key_file);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => return None,
        };

        let mut public = vec!();
        if file.read_to_end(&mut public).is_err() {
            return None;
        };

        Some(Keypair { public, private })
    }

    fn write_keys_to_file(&self) -> Result<()> {
        // Write the private key to a file
        let (private_key_file, public_key_file) = Self::key_filenames();
        let path = Path::new(private_key_file);
        let mut file = OpenOptions::new().read(true).write(true).truncate(true).create(true).open(path)?;
        file.write_all(&self.keypair().private)?;
	file.flush()?;

        // Write the public key to a file
        let path = Path::new(public_key_file);
        let mut file = OpenOptions::new().read(true).write(true).truncate(true).create(true).open(path)?;
	println!("Size {}", &self.keypair().public.len());
        file.write_all(&self.keypair().public)?;
	file.flush()?;

        Ok(())
    }
}
