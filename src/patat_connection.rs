use std::net::UdpSocket;

pub struct PatatConnection {
    socket: UdpSocket,
    peer_address: String,
}

impl PatatConnection {
    pub fn new(peer_address: String, listening_port: u16) -> Self {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", listening_port)).unwrap();
        PatatConnection {
            peer_address,
            socket,
        }
    }

    pub fn send_data(&self, message_buffer: &[u8]) -> std::io::Result<()> {
        self.socket
            .connect(&self.peer_address)
            .expect("Couldn't connect");
        let message_length_buffer = [
            (message_buffer.len() >> 8) as u8,
            (message_buffer.len() & 0xff) as u8,
        ];
        self.socket.send(&message_length_buffer)?;
        self.socket.send(&message_buffer)?;
        Ok(())
    }

    pub fn receive_data(&self) -> std::io::Result<Vec<u8>> {
        let mut receive_buffer = [0u8; 2];
        self.socket.recv(&mut receive_buffer)?;
        let message_length = ((receive_buffer[0] as usize) << 8) + (receive_buffer[1] as usize);

        let mut message = vec![0u8; message_length];
        self.socket.recv(&mut message)?;
        Ok(message)
    }
}
