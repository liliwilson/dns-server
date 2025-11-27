use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u8, be_u16},
};
pub fn parse_packet(packet: &[u8]) -> IResult<&[u8], Packet> {
    // Parse 96 bits of the header
    let (remaining, header) = parse_header(packet)?;
    // Parse questions
    let (remaining, questions) = parse_questions(remaining, header.q_count)?;

    Ok((remaining, Packet { header, questions }))
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

#[derive(Debug)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
}
#[derive(Debug)]
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

#[derive(Debug)]
struct Question {
    labels: Vec<String>,
    q_type: u16,
    q_class: u16,
}
