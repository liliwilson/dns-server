use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32},
};
pub fn parse_packet(packet: &[u8]) -> IResult<&[u8], Packet> {
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

fn parse_header(packet: &[u8]) -> IResult<&[u8], Header> {
    // TODO make this cleaner
    let (remaining, id) = be_u16(packet)?;
    let (remaining, flags) = be_u16(remaining)?;
    let (remaining, q_count) = be_u16(remaining)?;
    let (remaining, a_count) = be_u16(remaining)?;
    let (remaining, ns_count) = be_u16(remaining)?;
    let (remaining, ar_count) = be_u16(remaining)?;

    Ok((
        remaining,
        Header {
            id,
            flags,
            q_count,
            a_count,
            ns_count,
            ar_count,
        },
    ))
}

fn parse_questions(packet: &[u8], q_count: u16) -> IResult<&[u8], Vec<Question>> {
    let mut questions = Vec::new();
    let mut remaining = packet;

    for _ in 0..q_count {
        let (output, question) = parse_question(remaining)?;
        remaining = output;
        questions.push(question);
    }

    Ok((remaining, questions))
}

fn parse_question(packet: &[u8]) -> IResult<&[u8], Question> {
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

    let (remaining, q_type) = be_u16(remaining)?;
    let (remaining, q_class) = be_u16(remaining)?;

    Ok((
        remaining,
        Question {
            labels,
            q_type,
            q_class,
        },
    ))
}

fn parse_answers(packet: &[u8], a_count: u16) -> IResult<&[u8], Vec<Answer>> {
    let mut answers = Vec::new();
    let mut remaining = packet;

    for _ in 0..a_count {
        let (output, answer) = parse_answer(remaining)?;
        remaining = output;
        answers.push(answer);
    }

    Ok((remaining, answers))
}

fn parse_answer(packet: &[u8]) -> IResult<&[u8], Answer> {
    let (remaining, a_name) = parse_a_name(packet)?;
    let (remaining, a_type) = be_u16(remaining)?;
    let (remaining, a_class) = be_u16(remaining)?;
    let (remaining, ttl) = be_u32(remaining)?;
    let (remaining, rdlength) = be_u16(remaining)?;
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

fn parse_a_name(packet: &[u8]) -> IResult<&[u8], Name> {
    let (mut remaining, mut name_len) = be_u8(packet)?;

    // Check if the label name is compressed by looking at the two high bits
    if (name_len & 0b1100_0000) == 0b1100_0000 {
        let (output, offset_low) = be_u8(remaining)?;
        remaining = output;

        let offset_high = name_len & 0b0011_1111;
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

        Ok((remaining, Name::Labels(labels)))
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

#[derive(Debug, PartialEq)]
struct Question {
    labels: Vec<String>,
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
    Labels(Vec<String>),
    /// When we use compression, this represents an offset into the original packet
    Offset(u16),
}

#[path = "parse_tests.rs"]
mod tests;
