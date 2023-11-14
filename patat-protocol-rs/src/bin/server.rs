use patat_protocol_rs::server;


fn main() {
    let server = server::Server::new();

    server.run_server().expect("Could not run server");
}
