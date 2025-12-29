use std::{
    cell::{Ref, RefCell, RefMut},
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
};

use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{map, map_res, peek, verify},
    error::{Error, ErrorKind},
    multi::count,
    number::complete::{be_u8, be_u16, be_u32},
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
        name_parts.extend(extra.iter().cloned()); // TODO verify
    } else {
        // consume the null terminator for the literal label
        let (output, _) = be_u8(remaining)?;
        remaining = output;
    }

    let labels: DomainName = name_parts.into();

    {
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
        41 => RecordType::OPT,
        val => RecordType::UNSUPPORTED(val),
    })
    .parse(packet)
}

fn parse_record_data(packet: Span, rdlength: u16, r_type: RecordType) -> IResult<Span, RecordData> {
    match r_type {
        RecordType::A => {
            // TODO use `context` and `VerboseError`
            map(verify(be_u32, |_| rdlength == 4), |rdata: u32| {
                RecordData::AddressData(Ipv4Addr::from(rdata).into())
            })
            .parse(packet)
        }
        RecordType::AAAA => map_res(
            verify(take(16u8), |_| rdlength == 16),
            |rdata: Span| -> Result<RecordData, Error<Span>> {
                let parsed_addr = u128::from_be_bytes(
                    rdata
                        .fragment()
                        .to_vec()
                        .try_into()
                        .expect("Can convert to IPv6 address to u128"),
                );
                Ok(RecordData::AddressData(Ipv6Addr::from(parsed_addr).into()))
            },
        )
        .parse(packet),
        RecordType::NS => {
            let (remaining, domain_name) = parse_resource_name(packet)?;
            Ok((remaining, RecordData::NameServerData(domain_name)))
        }
        RecordType::OPT | RecordType::UNSUPPORTED(_) => map_res(
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
        self.build_record_type(&resource.r_type);
        self.write_u16(resource.class);
        self.write_u32(resource.ttl);
        self.write_u16(resource.rdlength);
        self.build_record_data(&resource.rdata);
    }

    /// Build up a domain name, using compression
    fn build_domain_name(&mut self, domain_name: DomainName) {
        let len = domain_name.len();

        // Loop through the label until we find a suffix in the cache.
        // Add to the cache if we don't have that suffix present.
        for i in 0..len {
            let label = &domain_name[i..len];
            let existing = self.label_cache.get(&label.to_vec());
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

    fn build_record_type(&mut self, record_type: &RecordType) {
        self.write_u16(match record_type {
            RecordType::A => 1,
            RecordType::AAAA => 2,
            RecordType::NS => 28,
            RecordType::OPT => 41,
            RecordType::UNSUPPORTED(val) => *val,
        });
    }

    fn build_record_data(&mut self, record_data: &RecordData) {
        match record_data {
            RecordData::AddressData(ipaddress) => match ipaddress {
                IpAddr::V4(ipv4_addr) => self.extend(&ipv4_addr.octets()),
                IpAddr::V6(ipv6_addr) => self.extend(&ipv6_addr.octets()),
            },
            RecordData::NameServerData(items) => self.build_domain_name(items.clone()),
            RecordData::Unsupported(items) => {
                self.extend(items);
            }
        };
    }
}

#[path = "parse_tests.rs"]
mod tests;
