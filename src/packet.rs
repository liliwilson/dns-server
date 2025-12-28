use std::{
    net::{Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Resource>,
    pub authorities: Vec<Resource>,
    pub additional_resources: Vec<Resource>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Header {
    /// Unique ID for the query
    pub id: u16,
    /// Flags
    // 1 bit of query response
    // 4 bits operation code [we just need this to be 0]
    // 1 bit of authoritative answer
    // 1 bit of truncated message
    // 1 bit of recursion desired
    // 1 bit of recursion available
    // 3 bits reserved [used by dnssec]
    // 4 bits response code
    pub flags: u16, // TODO use `bitflags` crate for this?
    /// Number of questions
    pub q_count: u16,
    /// Number of answers
    pub a_count: u16,
    /// Number of name servers
    pub ns_count: u16,
    /// Number of additional resources
    pub ar_count: u16,
}

// We use an `Rc` here because a label could be shared across multiple questions/answers due to
// compression
pub type DomainName = Rc<Vec<String>>;

#[derive(Debug, PartialEq)]
pub struct Question {
    pub labels: DomainName,
    pub q_type: u16,
    pub q_class: u16,
}

#[derive(Debug, PartialEq)]
pub struct Resource {
    pub name: DomainName,
    // TODO refactor so that we don't store r_type and rdlength -- just use rdata as canonical
    // source
    pub r_type: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: RecordData,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RecordType {
    A,
    AAAA,
    NS,
    OPT,
    UNSUPPORTED(u16),
}

#[derive(Debug, PartialEq)]
pub enum RecordData {
    AddressData(IPAddress),
    NameServerData(DomainName),
    Unsupported(Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum IPAddress {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
}

impl IPAddress {
    pub fn to_string(&self) -> String {
        match self {
            IPAddress::IPv4(a) => {
                let addr = Ipv4Addr::from(a.clone());
                addr.to_string()
            }
            IPAddress::IPv6(a) => {
                let addr = Ipv6Addr::from(a.clone()); // TODO no clone
                addr.to_string()
            }
        }
    }
}

impl Header {
    pub fn is_query(&self) -> bool {
        self.flags & (1 << 15) != 0
    }

    pub fn is_authoritative_answer(&self) -> bool {
        self.flags & (1 << 10) != 0
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & (1 << 9) != 0
    }
    pub fn is_recursion_desired(&self) -> bool {
        self.flags & (1 << 8) != 0
    }
    pub fn is_recursion_available(&self) -> bool {
        self.flags & (1 << 7) != 0
    }

    pub fn get_rcode(&self) -> u16 {
        self.flags & 0x000F
    }
}

impl Packet {
    pub fn new_query(domain_name: String, use_edns: bool) -> Packet {
        let labels: Rc<Vec<String>> =
            Rc::new(domain_name.split('.').map(|s| s.to_string()).collect());

        let mut ars = Vec::new();
        if use_edns {
            ars.push(Self::make_edns_record());
        }

        Packet {
            header: Header {
                id: 12345, // TODO fix
                flags: 0,  // TODO fix
                q_count: 1,
                a_count: 0,
                ns_count: 0,
                ar_count: ars.len() as u16,
            },
            questions: vec![Question {
                labels,
                q_type: 1,
                q_class: 1,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additional_resources: ars,
        }
    }

    fn make_edns_record() -> Resource {
        Resource {
            name: Rc::new(vec![]), // TODO default?
            r_type: RecordType::OPT,
            class: 4096, // UDP payload size
            ttl: 0,
            rdlength: 0,
            rdata: RecordData::Unsupported(vec![]),
        }
    }

    pub fn has_answer(&self) -> bool {
        // TODO rcode enum
        self.header.get_rcode() == 0 && self.header.a_count > 0
    }

    pub fn get_next_name_servers(&self) -> Vec<DomainName> {
        // look through authorities to get name server names
        // then look through additional resources to get addresses

        // get all NS domains
        // TODO handle authorities that aren't NS records
        let name_servers = self
            .authorities
            .iter()
            .filter_map(|ns| match &ns.rdata {
                RecordData::AddressData(_) => None,
                RecordData::NameServerData(items) => Some(items.clone()), // TODO yuck
                RecordData::Unsupported(_) => None,
            })
            .collect();

        name_servers
    }

    pub fn get_name_server_address(
        &self,
        domain_name: DomainName,
        // TODO this is sussss
        is_ipv4: bool,
    ) -> Option<&IPAddress> {
        // look through additional resources
        self.additional_resources
            .iter()
            .filter_map(|r| {
                if r.name != domain_name {
                    return None;
                }
                match &r.rdata {
                    RecordData::AddressData(ipaddress) => match ipaddress {
                        IPAddress::IPv4(a) => Some(ipaddress),
                        IPAddress::IPv6(_) => None,
                    },
                    _ => None,
                }
            })
            .next()
    }
}
