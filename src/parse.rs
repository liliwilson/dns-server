use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{BTreeMap, HashMap},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
    string::FromUtf8Error,
};

use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{map, map_res, peek},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::count,
    number::complete::{be_u8, be_u16, be_u32, be_u128},
};
use nom_locate::LocatedSpan;

use crate::packet::{DomainName, Header, Packet, Question, RecordData, RecordType, Resource};

/// We wrap the packet in `Span` to keep track of offset information to decompress as we parse.
/// Using Rc + RefCell because nom_locate clones the `extra` every time, but we  don't actually want
/// to clone the full hashmap.
pub type Span<'a> = LocatedSpan<&'a [u8], Rc<RefCell<ParseContext>>>;

/// Define a trait to make it easier to grab the context `extra` from Span,
/// which is defined in an external crate (hence the new trait).
pub trait HasParseContext {
    fn get_context(&self) -> Ref<'_, ParseContext>;

    fn get_context_mut(&self) -> RefMut<'_, ParseContext>;
}

impl HasParseContext for Span<'_> {
    fn get_context(&self) -> Ref<'_, ParseContext> {
        self.extra.borrow()
    }

    fn get_context_mut(&self) -> RefMut<'_, ParseContext> {
        self.extra.borrow_mut()
    }
}

#[derive(Default, Debug)]
pub struct ParseContext {
    q_count: u16,
    a_count: u16,
    ns_count: u16,
    ar_count: u16,
    /// We use this map to track labels at offsets so we can decompress as we parse.
    label_cache: BTreeMap<u16, DomainName>,
}

impl ParseContext {
    pub fn new() -> Rc<RefCell<ParseContext>> {
        Rc::new(RefCell::new(ParseContext::default()))
    }

    /// Given a header, populate the count values in the context
    fn populate_with_header(&mut self, header: &Header) {
        self.q_count = header.q_count;
        self.a_count = header.a_count;
        self.ns_count = header.ns_count;
        self.ar_count = header.ar_count;
    }
}

#[derive(Debug)]
pub enum DnsParseError<I> {
    /// Generic nom parse error
    Nom(I, ErrorKind),
    /// Compression pointer references invalid/unknown offset
    InvalidCompressionOffset { offset: u16, input: I },
    /// Record data length doesn't match expected for record type
    InvalidRdlength {
        expected: u16,
        actual: u16,
        record_type: u16,
        input: I,
    },
    /// Domain label contains invalid UTF-8
    InvalidUtf8Label { input: I },
}

impl<I> ParseError<I> for DnsParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        DnsParseError::Nom(input, kind)
    }

    // For now, not implementing any sort of error tracing
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> FromExternalError<I, FromUtf8Error> for DnsParseError<I> {
    fn from_external_error(input: I, _kind: ErrorKind, _e: FromUtf8Error) -> Self {
        DnsParseError::InvalidUtf8Label { input }
    }
}

impl<I: fmt::Debug> fmt::Display for DnsParseError<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsParseError::Nom(input, kind) => write!(f, "parse error {:?} at {:?}", kind, input),
            DnsParseError::InvalidCompressionOffset { offset, input } => {
                write!(f, "invalid compression offset {} at {:?}", offset, input)
            }
            DnsParseError::InvalidRdlength {
                expected,
                actual,
                record_type,
                input,
            } => {
                write!(
                    f,
                    "invalid rdlength for {:?}: expected {}, got {} at {:?}",
                    record_type, expected, actual, input
                )
            }
            DnsParseError::InvalidUtf8Label { input } => {
                write!(f, "invalid UTF-8 in label at {:?}", input)
            }
        }
    }
}

// Define type for parse results that return our custom DNS error type
type ParseResult<'a, O> = IResult<Span<'a>, O, DnsParseError<Span<'a>>>;

pub fn parse_packet(packet: Span) -> ParseResult<Packet> {
    map(
        (
            parse_header,
            parse_questions,
            parse_answers,
            parse_authorities,
            parse_additional_resources,
        ),
        |(header, questions, answers, authorities, additional_resources)| Packet {
            header,
            questions,
            answers,
            authorities,
            additional_resources,
        },
    )
    .parse(packet)
}

fn parse_header(packet: Span) -> ParseResult<Header> {
    let (res, header) = map(
        (be_u16, be_u16, be_u16, be_u16, be_u16, be_u16),
        |(id, flags, q_count, a_count, ns_count, ar_count)| Header {
            id,
            flags,
            q_count,
            a_count,
            ns_count,
            ar_count,
        },
    )
    .parse(packet)?;

    // Update the parse context with header values
    res.get_context_mut().populate_with_header(&header);

    Ok((res, header))
}

fn parse_questions(packet: Span) -> ParseResult<Vec<Question>> {
    let q_count = packet.get_context().q_count as usize;
    count(parse_question, q_count).parse(packet)
}

fn parse_question(packet: Span) -> ParseResult<Question> {
    map(
        (parse_resource_name, be_u16, be_u16),
        |(labels, q_type, q_class)| Question {
            labels,
            q_type,
            q_class,
        },
    )
    .parse(packet)
}

fn parse_answers(packet: Span) -> ParseResult<Vec<Resource>> {
    let a_count = packet.get_context().a_count as usize;
    count(parse_resource, a_count).parse(packet)
}

fn parse_authorities(packet: Span) -> ParseResult<Vec<Resource>> {
    let ns_count = packet.get_context().ns_count as usize;
    count(parse_resource, ns_count).parse(packet)
}

fn parse_additional_resources(packet: Span) -> ParseResult<Vec<Resource>> {
    let ar_count = packet.get_context().ar_count as usize;
    count(parse_resource, ar_count).parse(packet)
}

fn parse_resource(packet: Span) -> ParseResult<Resource> {
    let (remaining, (name, r_type, class, ttl, rdlength)) =
        (parse_resource_name, be_u16, be_u16, be_u32, be_u16).parse(packet)?;
    let (remaining, rdata) = parse_record_data(remaining, rdlength, r_type)?;

    Ok((
        remaining,
        Resource {
            name,
            class,
            ttl,
            rdata,
        },
    ))
}

fn parse_resource_name(packet: Span) -> ParseResult<DomainName> {
    let name_offset = packet.location_offset() as u16;
    let mut name_parts = Vec::new();
    let mut remaining = packet;

    // Peek at the next bit to check if this is a compressed name or not before parsing
    let (_, mut offset) = peek(be_u8).parse(remaining.clone())?;

    while (offset & COMPRESSION_MASK) != COMPRESSION_MASK && offset != 0 {
        let (output, label_part) = parse_literal_label(remaining)?;
        remaining = output;
        name_parts.push(label_part);
        (_, offset) = peek(be_u8).parse(remaining.clone())?;
    }

    if (offset & COMPRESSION_MASK) == COMPRESSION_MASK {
        let (output, extra) = parse_compressed_label(remaining)?;
        remaining = output;
        name_parts.extend(Arc::unwrap_or_clone(extra.0)); // TODO verify
    } else {
        // consume the null terminator for the literal label
        let (output, _) = be_u8(remaining)?;
        remaining = output;
    }

    let labels: DomainName = name_parts.into();

    {
        let mut ctx = remaining.get_context_mut();
        ctx.label_cache.insert(name_offset, labels.arc_clone());
    }

    Ok((remaining, labels))
}

fn parse_record_data(packet: Span, rdlength: u16, r_type: u16) -> ParseResult<RecordData> {
    match RecordType(r_type) {
        RecordType::A => {
            if rdlength != 4 {
                return Err(nom::Err::Failure(DnsParseError::InvalidRdlength {
                    expected: 4,
                    actual: rdlength,
                    record_type: r_type,
                    input: packet,
                }));
            }
            map(be_u32, |rdata: u32| {
                RecordData::Address(Ipv4Addr::from(rdata).into())
            })
            .parse(packet)
        }
        RecordType::AAAA => {
            if rdlength != 16 {
                return Err(nom::Err::Failure(DnsParseError::InvalidRdlength {
                    expected: 4,
                    actual: rdlength,
                    record_type: r_type,
                    input: packet,
                }));
            }

            map(be_u128, |rdata: u128| {
                RecordData::Address(Ipv6Addr::from(rdata).into())
            })
            .parse(packet)
        }
        RecordType::NS => {
            let (remaining, domain_name) = parse_resource_name(packet)?;
            Ok((remaining, RecordData::NameServer(domain_name)))
        }
        RecordType::OPT => Ok((packet, RecordData::Opt)),
        RecordType(r_type) => map(take(rdlength), |rdata: Span| RecordData::Unsupported {
            rdata: rdata.to_vec(),
            r_type,
        })
        .parse(packet),
    }
}

fn parse_compressed_label(packet: Span) -> ParseResult<DomainName> {
    // Grab the full offset, which is the next two bytes
    let (remaining, mut name_offset) = be_u16(packet.clone())?;

    // Remove the two high bits to get the actual offset
    name_offset &= !((COMPRESSION_MASK as u16) << 8);

    // Read the value at `name_offset` from the label cache
    let ctx = remaining.extra.borrow_mut();
    let labels = get_label_from_cache(ctx, name_offset);

    match labels {
        Some(labels) => Ok((remaining, labels)),
        None => Err(nom::Err::Failure(DnsParseError::InvalidCompressionOffset {
            offset: name_offset,
            input: packet,
        })),
    }
}

// This method returns an option, not an offset so that its caller can include the full packet in
// any error messages it needs to create due to invalid offsets.
fn get_label_from_cache(mut ctx: RefMut<ParseContext>, offset: u16) -> Option<DomainName> {
    let Some((label_offset, label)) = ctx.label_cache.range(..=offset).next_back() else {
        // If we don't have a valid offset, return None
        return None;
    };

    // If we have an exact match in the cache, return it
    if label_offset == &offset {
        return Some(label.arc_clone());
    }

    // Otherwise if we don't have key explicitly, it's a sub-part of another label
    let mut amount = offset - label_offset;

    let domain_parts = label.to_vec();
    let mut label_iter = domain_parts.into_iter().peekable();

    while let Some(label_part) = label_iter.peek() {
        let label_len = label_part.len() as u16;
        if amount < label_len {
            break;
        }
        amount -= label_len + 1;
        label_iter.next(); // consume this element
    }

    // Collect the label parts after the offset
    let offset_label: DomainName = label_iter.collect::<Vec<String>>().into();
    if offset_label.is_empty() {
        return None;
    }

    // Add to the cache; it's likely that other parts of the answer might use this
    ctx.label_cache.insert(offset, offset_label.arc_clone());

    Some(offset_label)
}

/// Given a packet where the next byte is the start of a label (label length),
/// parse that part of the label and return a String.
fn parse_literal_label(packet: Span) -> ParseResult<String> {
    let (remaining, name_len) = be_u8(packet)?;

    map_res(take(name_len), |output: Span| {
        String::from_utf8(output.fragment().to_vec())
    })
    .parse(remaining)
}

/// The upper two bits of the first label byte being set indicate that compression is being used
const COMPRESSION_MASK: u8 = 0b11 << 6;

pub struct PacketBuilder {
    output: Vec<u8>,
    label_cache: HashMap<Vec<String>, u16>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            output: Vec::new(),
            label_cache: HashMap::new(),
        }
    }

    fn position(&self) -> u16 {
        self.output.len() as u16
    }

    fn write_u8(&mut self, value: u8) {
        self.output.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.output.extend_from_slice(&value.to_be_bytes());
    }

    fn extend(&mut self, vec: &[u8]) {
        self.output.extend_from_slice(vec);
    }

    pub fn build(&mut self, packet: Packet) -> &[u8] {
        // Take apart the packet for consumption
        let Packet {
            header,
            questions,
            answers,
            authorities,
            additional_resources,
        } = packet;

        self.build_header(header);
        self.build_questions(questions);
        self.build_resources(answers);
        self.build_resources(authorities);
        self.build_resources(additional_resources);

        &self.output
    }

    fn build_header(&mut self, header: Header) {
        self.write_u16(header.id);
        self.write_u16(header.flags);
        self.write_u16(header.q_count);
        self.write_u16(header.a_count);
        self.write_u16(header.ns_count);
        self.write_u16(header.ar_count);
    }

    fn build_questions(&mut self, questions: Vec<Question>) {
        for question in questions {
            self.build_question(question);
        }
    }

    fn build_question(&mut self, question: Question) {
        self.build_domain_name(question.labels);
        self.write_u16(question.q_type);
        self.write_u16(question.q_class);
    }

    fn build_resources(&mut self, resources: Vec<Resource>) {
        for resource in resources {
            self.build_resource(resource);
        }
    }

    fn build_resource(&mut self, resource: Resource) {
        self.build_domain_name(resource.name);
        self.build_record_type(&resource.rdata);
        self.write_u16(resource.class);
        self.write_u32(resource.ttl);

        let rdlength = match &resource.rdata {
            RecordData::Address(ip_addr) => match ip_addr {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
            RecordData::NameServer(domain_name) => domain_name.serialized_len(),
            RecordData::Opt => 0,
            RecordData::Unsupported { rdata, r_type: _ } => rdata.len() as u16,
        };
        self.write_u16(rdlength);

        self.build_record_data(&resource.rdata);
    }

    /// Build up a domain name, using compression
    fn build_domain_name(&mut self, domain_name: DomainName) {
        let len = domain_name.len();

        // Loop through the label until we find a suffix in the cache.
        // Add to the cache if we don't have that suffix present.
        for i in 0..len {
            let label = &domain_name[i..len];
            let existing = self.label_cache.get(label);
            if let Some(offset) = existing {
                // Cache hit; write the offset and return early.
                let value = offset | ((COMPRESSION_MASK as u16) << 8);
                self.write_u16(value);
                return;
            } else {
                // Add to the label cache and continue.
                self.label_cache.insert(label.to_vec(), self.position());

                // Add the length and label to the packet.
                self.write_u8(domain_name[i].len() as u8);
                for c in domain_name[i].chars() {
                    self.write_u8(c as u8);
                }
            }
        }

        // Terminate label (root, len 0)
        self.write_u8(0x00);
    }

    fn build_record_type(&mut self, rdata: &RecordData) {
        let r_type = match rdata {
            RecordData::Address(ip_addr) => match ip_addr {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            },
            RecordData::NameServer(_) => RecordType::NS,
            RecordData::Opt => RecordType::OPT,
            RecordData::Unsupported { rdata: _, r_type } => RecordType(*r_type),
        };
        self.write_u16(r_type.0);
    }

    fn build_record_data(&mut self, record_data: &RecordData) {
        match record_data {
            RecordData::Address(ipaddress) => match ipaddress {
                IpAddr::V4(ipv4_addr) => self.extend(&ipv4_addr.octets()),
                IpAddr::V6(ipv6_addr) => self.extend(&ipv6_addr.octets()),
            },
            RecordData::NameServer(domain_name) => self.build_domain_name(domain_name.arc_clone()),
            RecordData::Opt => {}
            RecordData::Unsupported { rdata, r_type: _ } => {
                self.extend(rdata);
            }
        };
    }
}

#[path = "parse_tests.rs"]
mod tests;
