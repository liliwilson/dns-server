use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8080").await?;

    // Default DNS packet size is 512 bytes
    // TODO(lili) EDNS in the far future
    let mut buf = [0; 512];

    loop {
        let (bytes, src_addr) = socket.recv_from(&mut buf).await?;

        let packet = &buf[..bytes];

        println!("Got {} bytes from {}", bytes, src_addr);
        println!("Data: {:?}", &buf[..bytes]);

        // TODO all of the logic here

        let response = packet;
        socket.send_to(response, src_addr).await?;
    }
}
