mod client;
mod keys;
mod patat_connection;
mod server;
mod handshake;

use clap::Command;

fn main() {
    let command = Command::new("patat-protocol")
        .subcommand(Command::new("server").about("Start a PATAT Server"))
        .subcommand(Command::new("client").about("Start the PATAT Client"))
        .version("0.1.0")
        .about("The PATAT protocol CLI")
        .get_matches();

    let (builder, client_keypair, server_keypair) =
        keys::get_keys().expect("Could not generate keys!");

    match command.subcommand() {
        Some(("server", _subcommand_matches)) => {
            println!("Starting the UDP server...");
            server::run_server(builder, server_keypair);
        }
        Some(("client", _subcommand_matches)) => {
            println!("Starting the UPD client...");
	    let patat_client = client::Client::new();
            patat_client.run_client()
                .expect("Something went wrong on the client");
        }
        None => {
            println!("Called without subcommand");
        }
        _ => {
            panic!("Unknown command");
        }
    };
}

