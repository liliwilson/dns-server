use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::map_res,
    multi::count,
    number::complete::{be_u8, be_u16, be_u32},
};
use nom_locate::LocatedSpan;
// We wrap the packet in this to keep track of offset information in order to decompress it
pub type Span<'a> = LocatedSpan<&'a [u8]>;

pub fn parse_packet(packet: Span) -> IResult<Span, Packet> {
    // Parse 96 bits of the header
    let (remaining, header) = parse_header(packet)?;
    // Parse questions
    let (remaining, questions) = parse_questions(remaining, header.q_count)?;
    // Parse answers
    let (remaining, answers) = parse_answers(remaining, header.a_count)?;

    Ok((
        remaining,
        Packet {
            header,
            questions,
            answers,
        },
    ))
}

fn parse_header(packet: Span) -> IResult<Span, Header> {
    map_res(
        count(be_u16::<_, nom::error::Error<_>>, 6),
        Header::try_from,
    )
    .parse(packet)
}

fn parse_questions<'a>(packet: Span, q_count: u16) -> IResult<Span, Vec<Question>> {
    let mut questions = Vec::new();
    let mut remaining = packet;

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

    Ok((
        remaining,
        Question {
            labels: Name::Labels { labels, offset },
            q_type,
            q_class,
        },
    ))
}

fn parse_answers<'a>(packet: Span, a_count: u16) -> IResult<Span, Vec<Answer>> {
    let mut answers = Vec::new();
    let mut remaining = packet;

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

fn parse_a_name<'a>(packet: Span) -> IResult<Span, Name> {
    let (mut remaining, mut name_len) = be_u8(packet)?;

    // Check if the label name is compressed by looking at the two high bits
    let compression_mask = 0b11 << 6;
    if (name_len & compression_mask) == compression_mask {
        let (output, offset_low) = be_u8(remaining)?;
        remaining = output;

        let offset_high = name_len & !compression_mask;
        let offset = (offset_high as u16) << 8 | (offset_low as u16);

        Ok((remaining, Name::Offset(offset)))
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

        Ok((remaining, Name::Labels { labels, offset: 0 }))
    }
}

#[derive(Debug)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Answer>,
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

#[derive(Debug, PartialEq)]
struct Question {
    labels: Name,
    q_type: u16,
    q_class: u16,
}

#[derive(Debug, PartialEq)]
struct Answer {
    a_name: Name,
    a_type: u16,
    a_class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

#[derive(Debug, PartialEq)]
enum Name {
    Labels {
        labels: Vec<String>,
        offset: u16,
    },
    /// When we use compression, this represents an offset into the original packet
    Offset(u16),
}

#[path = "parse_tests.rs"]
mod tests;
