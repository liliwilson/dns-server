use std::{fmt::Display, net::IpAddr, ops::Deref, rc::Rc};

use rand::Rng;

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
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DomainName(pub Rc<Vec<String>>);

impl Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}

impl Deref for DomainName {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<String>> for DomainName {
    fn from(value: Vec<String>) -> Self {
        DomainName(Rc::new(value))
    }
}

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
    AddressData(IpAddr),
    NameServerData(DomainName),
    Unsupported(Vec<u8>),
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
        let labels: Vec<String> = domain_name.split('.').map(|s| s.to_string()).collect();

        let mut ars = Vec::new();
        if use_edns {
            ars.push(Self::make_edns_record());
        }

        let id: u16 = rand::rng().random();

        Packet {
            header: Header {
                id,
                flags: 0, // TODO fix
                q_count: 1,
                a_count: 0,
                ns_count: 0,
                ar_count: ars.len() as u16,
            },
            questions: vec![Question {
                labels: labels.into(),
                q_type: 1,
                q_class: 1,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additional_resources: ars,
        }
    }

    pub fn new_answer(id: u16, domain_name: DomainName, answer_ip: IpAddr) -> Packet {
        let (r_type, rdata, rdlength) = match answer_ip {
            IpAddr::V4(_) => (RecordType::A, RecordData::AddressData(answer_ip), 4),
            IpAddr::V6(_) => (RecordType::AAAA, RecordData::AddressData(answer_ip), 16),
        };

        Packet {
            header: Header {
                id,
                flags: 0b1000_0100_0000_0000, // TODO fix
                q_count: 1,
                a_count: 1, // TODO don't hardcode
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                labels: domain_name.clone(),
                q_type: 1,
                q_class: 1,
            }],
            answers: vec![Resource {
                name: domain_name,
                r_type,
                class: 1, // Hardcoded IN class
                ttl: 300, //TODO hardocded
                rdlength,
                rdata,
            }],
            authorities: Vec::new(),
            additional_resources: Vec::new(),
        }
    }
    pub fn new_not_found(id: u16, domain_name: DomainName) -> Packet {
        Packet {
            header: Header {
                id,
                flags: 0b1000_0000_0000_0011, // TODO fix
                q_count: 1,
                a_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                labels: domain_name,
                q_type: 1,
                q_class: 1,
            }],
            answers: vec![],
            authorities: Vec::new(),
            additional_resources: Vec::new(),
        }
    }

    fn make_edns_record() -> Resource {
        Resource {
            name: DomainName::default(), // default to empty list
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
        self.authorities
            .iter()
            .filter_map(|ns| match &ns.rdata {
                RecordData::AddressData(_) => None,
                RecordData::NameServerData(items) => Some(items.clone()), // TODO yuck
                RecordData::Unsupported(_) => None,
            })
            .collect()
    }

    pub fn get_name_server_address(&self, domain_name: DomainName) -> Option<&IpAddr> {
        // look through additional resources
        self.additional_resources
            .iter()
            .filter_map(|r| {
                if r.name != domain_name {
                    return None;
                }
                match &r.rdata {
                    RecordData::AddressData(addr) => Some(addr),
                    RecordData::NameServerData(_) | RecordData::Unsupported(_) => None,
                }
            })
            .next()
    }
}
