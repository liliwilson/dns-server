use std::{
    cell::{Ref, RefCell, RefMut},
    collections::BTreeMap,
    rc::Rc,
};

use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{map, map_res, peek, verify},
    error::{Error, ErrorKind, ParseError},
    multi::count,
    number::complete::{be_u8, be_u16, be_u32},
};
use nom_locate::LocatedSpan;

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

pub fn parse_packet(packet: Span) -> IResult<Span, Packet> {
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

fn parse_header(packet: Span) -> IResult<Span, Header> {
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

fn parse_questions(packet: Span) -> IResult<Span, Vec<Question>> {
    let q_count = packet.get_context().q_count as usize;
    count(parse_question, q_count).parse(packet)
}

fn parse_question(packet: Span) -> IResult<Span, Question> {
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

fn parse_answers(packet: Span) -> IResult<Span, Vec<Resource>> {
    let a_count = packet.get_context().a_count as usize;
    count(parse_resource, a_count).parse(packet)
}

fn parse_authorities(packet: Span) -> IResult<Span, Vec<Resource>> {
    let ns_count = packet.get_context().ns_count as usize;
    count(parse_resource, ns_count).parse(packet)
}

fn parse_additional_resources(packet: Span) -> IResult<Span, Vec<Resource>> {
    let ar_count = packet.get_context().ar_count as usize;
    count(parse_resource, ar_count).parse(packet)
}

fn parse_resource(packet: Span) -> IResult<Span, Resource> {
    let (remaining, (name, r_type, class, ttl, rdlength)) = (
        parse_resource_name,
        parse_record_type,
        be_u16,
        be_u32,
        be_u16,
    )
        .parse(packet)?;
    let (remaining, rdata) = parse_record_data(remaining, rdlength, r_type)?;

    Ok((
        remaining,
        Resource {
            name,
            r_type,
            class,
            ttl,
            rdlength,
            rdata,
        },
    ))
}

fn parse_resource_name(packet: Span) -> IResult<Span, DomainName> {
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
        name_parts.extend(extra.as_ref().iter().cloned()); // TODO verify
    } else {
        // consume the null terminator for the literal label
        let (output, _) = be_u8(remaining)?;
        remaining = output;
    }

    let labels = Rc::new(name_parts);

    {
        println!("inserting {:?} at {:?}", labels, name_offset);
        let mut ctx = remaining.get_context_mut();
        ctx.label_cache.insert(name_offset, labels.clone());
    }

    Ok((remaining, labels))
}

fn parse_record_type(packet: Span) -> IResult<Span, RecordType> {
    map(be_u16, |rtype| match rtype {
        1 => RecordType::A,
        2 => RecordType::NS,
        28 => RecordType::AAAA,
        val => RecordType::UNSUPPORTED(val),
    })
    .parse(packet)
}

fn parse_record_data(packet: Span, rdlength: u16, r_type: RecordType) -> IResult<Span, RecordData> {
    match r_type {
        RecordType::A => {
            // TODO use `context` and `VerboseError`
            map_res(
                verify(take(4u8), |_| rdlength == 4),
                |rdata: Span| -> Result<RecordData, Error<Span>> {
                    let parsed = rdata.fragment().to_vec().try_into();

                    match parsed {
                        Ok(rdata) => Ok(RecordData::AddressData(IPAddress::IPv4(rdata))),
                        Err(_) => Err(Error::new(rdata, ErrorKind::Verify)),
                    }
                },
            )
            .parse(packet)
        }
        RecordType::AAAA => map_res(
            verify(take(16u8), |_| rdlength == 16),
            |rdata: Span| -> Result<RecordData, Error<Span>> {
                let parsed = rdata.fragment().to_vec().try_into();

                match parsed {
                    Ok(rdata) => Ok(RecordData::AddressData(IPAddress::IPv6(rdata))),
                    Err(_) => Err(Error::new(rdata, ErrorKind::Verify)),
                }
            },
        )
        .parse(packet),
        RecordType::NS => {
            let (remaining, domain_name) = parse_resource_name(packet)?;
            Ok((remaining, RecordData::NameServerData(domain_name)))
        }
        RecordType::UNSUPPORTED(_) => map_res(
            take(rdlength),
            |rdata: Span| -> Result<RecordData, Error<Span>> {
                Ok(RecordData::Unsupported(rdata.to_vec()))
            },
        )
        .parse(packet),
    }
}

fn parse_compressed_label(packet: Span) -> IResult<Span, DomainName> {
    // Grab the full offset, which is the next two bytes
    let (remaining, mut name_offset) = be_u16(packet)?;

    // Remove the two high bits to get the actual offset
    name_offset = name_offset & !((COMPRESSION_MASK as u16) << 8);

    // Read the value at `name_offset` from the label cache
    let ctx = remaining.extra.borrow_mut();
    let labels = get_label_from_cache(ctx, name_offset);

    match labels {
        Some(labels) => Ok((remaining, labels)),
        None => Err(nom::Err::Failure(Error::new(remaining, ErrorKind::Verify))),
    }
}

fn get_label_from_cache(mut ctx: RefMut<ParseContext>, offset: u16) -> Option<DomainName> {
    let Some((label_offset, label)) = ctx.label_cache.range(..=offset).next_back() else {
        // If we don't have a valid offset, return None
        return None;
    };

    // If we have an exact match in the cache, return it
    if label_offset == &offset {
        return Some(label.clone());
    }

    // Otherwise if we don't have key explicitly, it's a sub-part of another label
    let mut amount = offset - label_offset;

    let domain_parts = label.as_ref().clone();
    let mut label_iter = domain_parts.into_iter().peekable();

    while let Some(label_part) = label_iter.peek() {
        if amount <= 0 {
            break;
        }
        amount -= label_part.len() as u16 + 1;
        label_iter.next(); // consume this element
    }

    // Collect the label parts after the offset
    let offset_label: Rc<Vec<String>> = label_iter.collect::<Vec<String>>().into();
    if offset_label.is_empty() {
        return None;
    }

    // Add to the cache; it's likely that other parts of the answer might use this
    ctx.label_cache.insert(offset, offset_label.clone());

    return Some(offset_label);
}

/// Given a packet where the next byte is the start of a label (label length),
/// parse that part of the label and return a String.
fn parse_literal_label(packet: Span) -> IResult<Span, String> {
    let (remaining, name_len) = be_u8(packet)?;

    // TODO check error here
    map_res(take(name_len), |output: Span| {
        String::from_utf8(output.fragment().to_vec())
    })
    .parse(remaining)
}

/// The upper two bits of the first label byte being set indicate that compression is being used
const COMPRESSION_MASK: u8 = 0b11 << 6;

#[derive(Debug)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Resource>,
    authorities: Vec<Resource>,
    additional_resources: Vec<Resource>,
}

#[derive(Debug, PartialEq)]
struct Header {
    /// Unique ID for the query
    id: u16,
    /// Flags
    // 1 bit of query response
    // 4 bits operation code [we just need this to be 0]
    // 1 bit of authoritative answer
    // 1 bit of truncated message
    // 1 bit of recursion desired
    // 1 bit of recursion available
    // 3 bits reserved [used by dnssec]
    // 4 bits response code
    flags: u16, // TODO use `bitflags` crate for this?
    /// Number of questions
    q_count: u16,
    /// Number of answers
    a_count: u16,
    /// Number of name servers
    ns_count: u16,
    /// Number of additional resources
    ar_count: u16,
}

// We use an `Rc` here because a label could be shared across multiple questions/answers due to
// compression
type DomainName = Rc<Vec<String>>;

#[derive(Debug, PartialEq)]
struct Question {
    labels: DomainName,
    q_type: u16,
    q_class: u16,
}

#[derive(Debug, PartialEq)]
struct Resource {
    name: DomainName,
    r_type: RecordType,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: RecordData,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RecordType {
    A,
    AAAA,
    NS,
    UNSUPPORTED(u16),
}

#[derive(Debug, PartialEq)]
enum RecordData {
    AddressData(IPAddress),
    NameServerData(DomainName),
    Unsupported(Vec<u8>),
}

#[derive(Debug, PartialEq)]
enum IPAddress {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
}

pub struct PacketBuilder {
    output: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self { output: Vec::new() }
    }

    pub fn build(&self, packet: Packet) -> Vec<u8> {
        // Take apart the packet for consumption
        let Packet {
            header,
            questions,
            answers,
            authorities,
            additional_resources,
        } = packet;

        let header = self.build_header(header);
        let questions = self.build_questions(questions);
        let answers = self.build_resources(answers);
        let authorities = self.build_resources(authorities);
        let additional_resources = self.build_resources(additional_resources);

        [
            header,
            questions,
            answers,
            authorities,
            additional_resources,
        ]
        .concat()
    }

    fn build_header(&self, header: Header) -> Vec<u8> {
        // TODO nicer?
        let mut query = Vec::with_capacity(12);
        query.extend_from_slice(&header.id.to_be_bytes());
        query.extend_from_slice(&header.flags.to_be_bytes());
        query.extend_from_slice(&header.q_count.to_be_bytes());
        query.extend_from_slice(&header.a_count.to_be_bytes());
        query.extend_from_slice(&header.ns_count.to_be_bytes());
        query.extend_from_slice(&header.ar_count.to_be_bytes());
        query
    }

    fn build_questions(&self, questions: Vec<Question>) -> Vec<u8> {
        questions
            .into_iter()
            .flat_map(|q| self.build_question(q))
            .collect()
    }

    fn build_question(&self, question: Question) -> Vec<u8> {
        let mut q_vec: Vec<u8> = Self::build_domain_name(question.labels);
        q_vec.extend_from_slice(&question.q_type.to_be_bytes());
        q_vec.extend_from_slice(&question.q_class.to_be_bytes());
        q_vec
    }

    fn build_resources(&self, resources: Vec<Resource>) -> Vec<u8> {
        resources
            .into_iter()
            .flat_map(|r| self.build_resource(r))
            .collect()
    }

    fn build_resource(&self, resource: Resource) -> Vec<u8> {
        let mut r_vec: Vec<u8> = Self::build_domain_name(resource.name);
        r_vec.extend_from_slice(&Self::build_record_type(&resource.r_type).to_be_bytes());
        r_vec.extend_from_slice(&resource.class.to_be_bytes());
        r_vec.extend_from_slice(&resource.ttl.to_be_bytes());
        r_vec.extend_from_slice(&resource.rdlength.to_be_bytes());
        r_vec.extend_from_slice(&Self::build_record_data(&resource.rdata));
        r_vec
    }

    fn build_domain_name(domain_name: DomainName) -> Vec<u8> {
        let mut name_vec: Vec<u8> = domain_name
            .iter()
            .flat_map(|label| {
                std::iter::once(label.len() as u8)
                    .chain(label.bytes())
                    .collect::<Vec<u8>>()
            })
            .collect();

        // Terminate label (root, len 0)
        name_vec.push(0x00);

        name_vec
    }

    fn build_record_type(record_type: &RecordType) -> u16 {
        match record_type {
            RecordType::A => 1,
            RecordType::AAAA => 2,
            RecordType::NS => 28,
            RecordType::UNSUPPORTED(val) => *val,
        }
    }

    fn build_record_data(record_data: &RecordData) -> Vec<u8> {
        match record_data {
            RecordData::AddressData(ipaddress) => match ipaddress {
                IPAddress::IPv4(add) => add.to_vec(),
                IPAddress::IPv6(add) => add.to_vec(),
            },
            RecordData::NameServerData(items) => Self::build_domain_name(items.clone()),
            RecordData::Unsupported(items) => items.to_vec(),
        }
    }
}

#[path = "parse_tests.rs"]
mod tests;
