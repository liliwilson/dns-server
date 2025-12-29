use std::collections::HashSet;

use tokio::net::UdpSocket;

mod packet;
mod parse;

use crate::{
    packet::{Packet, RecordData},
    parse::{PacketBuilder, ParseContext, Span, parse_packet},
};

const DNS_PORT: u16 = 53;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8080").await?;

    let mut buf = [0; 4096];

    loop {
        let (bytes, src_addr) = socket.recv_from(&mut buf).await?;

        let packet = &buf[..bytes];

        println!("Got {} bytes from {}", bytes, src_addr);
        let result = parse_packet(Span::new_extra(packet, ParseContext::new()));

        match result {
            Ok((_remaining, parsed)) => match parsed.questions.first() {
                Some(question) => {
                    let address = send_query(question.labels.to_string()).await;
                    println!("answer {address:?}");
                }
                None => println!("no question supplied, skipping"),
            },
            Err(e) => println!("ERROR {e:?}"),
        }
    }
}

#[derive(Debug)]
enum DNSError {
    NotFound,
    Io(std::io::Error),
    Parse(String),
}

impl From<std::io::Error> for DNSError {
    fn from(e: std::io::Error) -> Self {
        DNSError::Io(e)
    }
}

impl<E: std::fmt::Debug> From<nom::Err<E>> for DNSError {
    fn from(e: nom::Err<E>) -> Self {
        DNSError::Parse(format!("{:?}", e))
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum NameServer {
    IPAddress(String),
    DomainName(String),
}

/// Initialize the list of servers to check with known root servers.
fn root_servers() -> Vec<NameServer> {
    vec![
        NameServer::IPAddress("198.41.0.4".to_string()), // a.root-servers.net
    ]
}

async fn send_query(query_domain: String) -> Result<String, DNSError> {
    let out_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut name_servers = root_servers();
    let mut seen = HashSet::new();

    // build up a query packet
    let query_packet = Packet::new_query(query_domain.clone(), true);
    let mut builder = PacketBuilder::new();
    let query = builder.build(query_packet);

    while let Some(name_server) = name_servers.pop() {
        if !seen.insert(name_server.clone()) {
            println!("skipping, already saw {name_server:?}");
            continue;
        }

        let next_name_server = match &name_server {
            NameServer::IPAddress(ip) => ip,
            NameServer::DomainName(name) => {
                &Box::pin(send_query(name.clone())).await?
            }
        };

        let mut buf = [0; 4096];
        out_socket
            .send_to(query, &format!("{next_name_server}:{DNS_PORT}"))
            .await?;
        let (bytes, _) = out_socket.recv_from(&mut buf).await?;
        let (_, parsed_packet) = parse_packet(Span::new_extra(&buf[..bytes], ParseContext::new()))?;

        // If we have an answer and can get an IP address from it, return it
        if parsed_packet.has_answer() {
            if let RecordData::AddressData(ipaddr) = &parsed_packet.answers[0].rdata {
                return Ok(ipaddr.to_string());
            }
        }

        let nses = parsed_packet.get_next_name_servers();
        if nses.is_empty() {
            return Err(DNSError::NotFound);
        };

        println!("next ns {:?}", nses);
        for ns in nses {
            let ns_addr = parsed_packet.get_name_server_address(ns.clone());
            let new = match ns_addr {
                Some(addr) => {
                    if ns.to_string() == query_domain {
                        return Ok(addr.to_string());
                    }

                    NameServer::IPAddress(addr.to_string())
                }
                None => NameServer::DomainName(ns.to_string()),
            };

            name_servers.push(new);
        }
    }

    return Err(DNSError::NotFound);
}
