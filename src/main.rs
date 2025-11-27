use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8080")?;

    let mut buf = [0u8; 1024];

    loop {
        let (len, src) = socket.recv_from(&mut buf)?;

        println!("Got {} bytes from {}", len, src);

        println!("Data: {:?}", &buf[..len]);
    }
}
