use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
use tokio::net::UdpSocket;

mod packet;
mod parse;

use crate::{
    packet::{Packet, RecordData},
    parse::{PacketBuilder, ParseContext, Span, parse_packet},
};

const DNS_PORT: u16 = 53;
type DNSCache = Arc<DashMap<String, CachedAddr>>;
#[derive(Debug)]
struct CachedAddr {
    addr: IpAddr,
    expiration_time: SystemTime,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:8080").await?);
    let cache: DNSCache = DashMap::new().into();

    let mut buf = [0; 4096];

    loop {
        let (bytes, src_addr) = socket.recv_from(&mut buf).await?;
        let packet = &buf[..bytes];

        println!("Got {} bytes from {}", bytes, src_addr);
        let result = parse_packet(Span::new_extra(packet, ParseContext::new()));

        match result {
            Ok((_remaining, parsed)) => match parsed.questions.first() {
                Some(question) => {
                    // Clone variables so we can move them to the new task
                    let query_labels = question.labels.arc_clone();
                    let query_name = question.labels.to_string();
                    let query_id = parsed.header.id;
                    let socket_clone = Arc::clone(&socket);
                    let cache_clone = Arc::clone(&cache);

                    tokio::spawn(async move {
                        let address = send_query(query_name.clone(), cache_clone).await;
                        println!("\n\n\nAnswer: {address:?}");

                        let response_packet = match address {
                            Ok(a) => Packet::new_answer(query_id, query_labels.arc_clone(), a),
                            Err(e) => {
                                println!("DNS lookup error: {e:?}");
                                Packet::new_not_found(query_id, query_labels.arc_clone())
                            }
                        };

                        let mut builder = PacketBuilder::new();
                        let response = builder.build(response_packet);
                        socket_clone.send_to(response, src_addr).await
                    });
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

impl std::fmt::Display for DNSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DNSError::NotFound => write!(f, "DNS record not found"),
            DNSError::Io(e) => write!(f, "IO error: {}", e),
            DNSError::Parse(s) => write!(f, "parse error: {}", s),
        }
    }
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
    IPAddress(IpAddr),
    DomainName(String),
}

/// Initialize the list of servers to check with known root servers.
fn root_servers() -> Vec<NameServer> {
    vec![
        NameServer::IPAddress(Ipv4Addr::new(198, 41, 0, 4).into()), // a.root-servers.net
    ]
}

async fn send_query(query_domain: String, dns_cache: DNSCache) -> Result<IpAddr, DNSError> {
    if let Some(cached_addr) = dns_cache.get(&query_domain) {
        if SystemTime::now() < cached_addr.expiration_time {
            println!(
                "reading value for {query_domain:?} from cache: {:?} until {:?}",
                cached_addr.addr, cached_addr.expiration_time
            );
            return Ok(cached_addr.addr);
        }
    }

    let out_v4_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let out_v6_socket = UdpSocket::bind("[::]:0").await?;

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
                &Box::pin(send_query(name.clone(), Arc::clone(&dns_cache))).await?
            }
        };

        let out_socket = match next_name_server {
            IpAddr::V4(_) => &out_v4_socket,
            IpAddr::V6(_) => &out_v6_socket,
        };

        let mut buf = [0; 4096];
        out_socket
            .send_to(query, &format!("{next_name_server}:{DNS_PORT}"))
            .await?;
        let (bytes, _) = out_socket.recv_from(&mut buf).await?;
        let (_, parsed_packet) = parse_packet(Span::new_extra(&buf[..bytes], ParseContext::new()))?;

        // If we have an answer and can get an IP address from it, return it
        if parsed_packet.has_answer() {
            let answer: Option<(IpAddr, u32)> = parsed_packet.answers.iter().find_map(|answer| {
                if let RecordData::Address(addr) = answer.rdata {
                    Some((addr, answer.ttl))
                } else {
                    None
                }
            });

            if let Some((addr, ttl)) = answer {
                dns_cache.insert(
                    query_domain,
                    CachedAddr {
                        addr,
                        expiration_time: SystemTime::now() + Duration::from_secs(ttl as u64),
                    },
                );
                return Ok(addr);
            }
        }

        let nses = parsed_packet.get_next_name_servers();
        if nses.is_empty() {
            return Err(DNSError::NotFound);
        };

        println!("next ns {:?}", nses);
        for ns in nses {
            let ns_data = parsed_packet.get_name_server_address(ns.arc_clone());
            let new = match ns_data {
                Some((addr, ttl)) => {
                    if ns.to_string() == query_domain {
                        dns_cache.insert(
                            query_domain,
                            CachedAddr {
                                addr: *addr,
                                expiration_time: SystemTime::now()
                                    + Duration::from_secs(ttl as u64),
                            },
                        );
                        return Ok(*addr);
                    }

                    NameServer::IPAddress(*addr)
                }
                None => NameServer::DomainName(ns.to_string()),
            };

            name_servers.push(new);
        }
    }

    Err(DNSError::NotFound)
}
