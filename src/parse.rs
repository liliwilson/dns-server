use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    rc::Rc,
};

use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{map, map_res},
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
    label_cache: HashMap<u16, Label>,
}

impl ParseContext {
    pub fn new() -> Rc<RefCell<ParseContext>> {
        Rc::new(RefCell::new(ParseContext::default()))
    }
}

pub fn parse_packet(packet: Span) -> IResult<Span, Packet> {
    map(
        (parse_header, parse_questions, parse_answers),
        |(h, q, a)| Packet::new(h, q, a),
    )
    .parse(packet)
}

fn parse_header(packet: Span) -> IResult<Span, Header> {
    let (res, header) = map_res(
        count(be_u16::<_, nom::error::Error<_>>, 6),
        Header::try_from,
    )
    .parse(packet)?;

    // Update the parse context with header values
    {
        let mut ctx = res.get_context_mut();
        ctx.q_count = header.q_count;
        ctx.a_count = header.a_count;
        ctx.ns_count = header.ns_count;
        ctx.ar_count = header.ar_count;
    }

    Ok((res, header))
}

fn parse_questions<'a>(packet: Span) -> IResult<Span, Vec<Question>> {
    let q_count = packet.get_context().q_count;

    let (mut remaining, mut questions) = (packet, Vec::new());
    for _ in 0..q_count {
        let (output, question) = parse_question(remaining)?;
        remaining = output;
        questions.push(question);
    }

    Ok((remaining, questions))
}

fn parse_question<'a>(packet: Span) -> IResult<Span, Question> {
    // offset is stored as - 1 because DNS compression does 0 indexing but the package does 1
    // indexing
    let offset = packet.get_column().saturating_sub(1) as u16;
    let mut labels = Vec::new();

    let (mut remaining, mut labels_len) = be_u8(packet)?;

    // Keep pulling off parts of the domain name until we hit the root, which has len 0
    while labels_len != 0 {
        let (output, label) = take(labels_len)(remaining)?;
        // TODO is this the correct way to overwrite `remaining` without shadowing it??
        remaining = output;

        // TODO actually do nom error handling yeesh... cloudflare outage :eyes_emoji:
        let q_name = String::from_utf8(label.to_vec()).unwrap();
        labels.push(q_name);

        (remaining, labels_len) = be_u8(remaining)?;
    }

    let (remaining, (q_type, q_class)) = (be_u16, be_u16).parse(remaining)?;

    // Wrap labels in an `Rc` before adding to the cache
    let labels = Rc::new(labels);

    // Add to the label cache
    // Wrap in a closure so we drop the `remaining` borrow
    {
        let mut ctx = remaining.get_context_mut();
        ctx.label_cache.insert(offset, labels.clone());
    }

    Ok((
        remaining,
        Question {
            labels,
            q_type,
            q_class,
        },
    ))
}

fn parse_answers<'a>(packet: Span) -> IResult<Span, Vec<Answer>> {
    let a_count = packet.get_context().a_count;

    let (mut remaining, mut answers) = (packet, Vec::new());
    for _ in 0..a_count {
        let (output, answer) = parse_answer(remaining)?;
        remaining = output;
        answers.push(answer);
    }

    Ok((remaining, answers))
}

fn parse_answer<'a>(packet: Span) -> IResult<Span, Answer> {
    let (remaining, a_name) = parse_a_name(packet)?;
    let (remaining, (a_type, a_class, ttl, rdlength)) =
        (be_u16, be_u16, be_u32, be_u16).parse(remaining)?;
    let (remaining, rdata) = take(rdlength)(remaining)?;

    Ok((
        remaining,
        Answer {
            a_name,
            a_type,
            a_class,
            ttl,
            rdlength,
            rdata: rdata.to_vec(),
        },
    ))
}

fn parse_a_name<'a>(packet: Span) -> IResult<Span, Label> {
    let (mut remaining, mut name_len) = be_u8(packet)?;

    // Check if the label name is compressed by looking at the two high bits
    let compression_mask = 0b11 << 6;
    if (name_len & compression_mask) == compression_mask {
        let (output, offset_low) = be_u8(remaining)?;
        remaining = output;

        let offset_high = name_len & !compression_mask;
        let name_offset = (offset_high as u16) << 8 | (offset_low as u16);

        // Read from the label cache
        // Wrap in a closure so we drop the `remaining` borrow
        let labels;
        {
            let ctx = remaining.extra.borrow();
            labels = ctx
                .label_cache
                .get(&name_offset)
                .expect("offset should refer to a label")
                .clone();
        }

        Ok((remaining, labels))
    } else {
        // Keep pulling off parts of the domain name until we hit the root, which has len 0
        let mut labels = Vec::new();
        while name_len != 0 {
            let (output, label) = take(name_len)(remaining)?;
            remaining = output;

            let a_name = String::from_utf8(label.to_vec()).unwrap();
            labels.push(a_name);

            (remaining, name_len) = be_u8(remaining)?;
        }

        Ok((remaining, Rc::new(labels)))
    }
}

#[derive(Debug)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Answer>,
}

impl Packet {
    fn new(header: Header, questions: Vec<Question>, answers: Vec<Answer>) -> Packet {
        Packet {
            header,
            questions,
            answers,
        }
    }
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

impl TryFrom<Vec<u16>> for Header {
    type Error = &'static str;

    /// Takes a Vec<u16> with exactly 6 elements and parses it into a Header
    fn try_from(item: Vec<u16>) -> Result<Self, Self::Error> {
        let [id, flags, q_count, a_count, ns_count, ar_count]: [u16; 6] =
            item.try_into().map_err(|_| "expected 6 elements")?;

        Ok(Header {
            id,
            flags,
            q_count,
            a_count,
            ns_count,
            ar_count,
        })
    }
}

// We use an `Rc` here because a label could be shared across multiple questions/answers due to
// compression
type Label = Rc<Vec<String>>;

#[derive(Debug, PartialEq)]
struct Question {
    labels: Label,
    q_type: u16,
    q_class: u16,
}

#[derive(Debug, PartialEq)]
struct Answer {
    a_name: Label,
    a_type: u16,
    a_class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

#[path = "parse_tests.rs"]
mod tests;
