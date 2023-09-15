use snow::{Builder, Keypair};

use crate::{patat_connection::PatatConnection, handshake, keys};

pub struct Client {
    protocol_builder: Builder<'static>,
    client_key: Keypair,
    server_key: Keypair,
}

impl Client {
    pub fn new() -> Self {
	let (protocol_builder, client_key, server_key) = keys::get_keys().unwrap();
	Client {
	    protocol_builder,
	    client_key,
	    server_key,
	}
    }
    
    pub fn run_client(
	&self,
    ) -> std::io::Result<()> {
	let client_static_key = self.client_key.private;
	let connection = PatatConnection::new("127.0.0.1:5072".to_owned(), 5071);

	// Now we can go to the Transport mode since the handshake is done
	let mut transport = handshake::run_client_handshake(self.protocol_builder, self.client_key.private, self.server_key.public, &connection);
	let mut message_buf = vec![0u8; 65535];
	let message_len = transport.write_message(b"hello", &mut message_buf).unwrap();
	connection.send_data(&message_buf[..message_len]).unwrap();
	Ok(())
    }
}

