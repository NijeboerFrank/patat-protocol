use anyhow::Result;
use patat_protocol::{client, patat_participant::PatatParticipant, server};

fn main() -> Result<()> {
    println!("Starting the UPD client...");
    let patat_client = client::Client::new(server::Server::read_keys_from_file().unwrap());
    patat_client.run_client()?;

    Ok(())
}
