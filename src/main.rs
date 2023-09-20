mod client;
mod handshake;
mod patat_participant;
mod patat_connection;
mod server;
mod merkle_tree;

use clap::Command;

use crate::patat_participant::PatatParticipant;

fn main() {
    let command = Command::new("patat-protocol")
        .subcommand(Command::new("server").about("Start a PATAT Server"))
        .subcommand(Command::new("client").about("Start the PATAT Client"))
        .version("0.1.0")
        .about("The PATAT protocol CLI")
        .get_matches();

    match command.subcommand() {
        Some(("server", _subcommand_matches)) => {
            println!("Starting the UDP server...");
            let patat_server = server::Server::new();
            patat_server
                .run_server()
                .expect("Something went wrong on the server");
        }
        Some(("client", _subcommand_matches)) => {
            println!("Starting the UPD client...");
            let patat_client = client::Client::new(server::Server::read_keys_from_file().unwrap());
            patat_client
                .run_client()
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
