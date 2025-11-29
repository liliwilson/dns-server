#[cfg(test)]
use crate::parse::*;

#[cfg(test)]
fn build_question(target_domain: String) -> Vec<u8> {
    // Convert domain into labels
    let domain_parts: Vec<&str> = target_domain.split(".").collect();
    let mut question: Vec<u8> = domain_parts
        .into_iter()
        .map(|label| {
            std::iter::once(label.len() as u8)
                .chain(label.bytes())
                .collect::<Vec<u8>>()
        })
        .flatten()
        .collect();
    // Terminate label (root, len 0)
    question.push(0x00);

    // Add in QTYPE and QCLASS
    question.append(&mut vec![0x00, 0x01]); // type A
    question.append(&mut vec![0x00, 0x01]); // class IN

    question
}

#[cfg(test)]
fn build_query(query_domains: Vec<String>) -> Vec<u8> {
    let mut query = Vec::new();

    let id: u16 = 0x1234;
    query.extend_from_slice(&id.to_be_bytes());

    let flags: u16 = 0x0100; // flags: standard query
    query.extend_from_slice(&flags.to_be_bytes());

    let q_count: u16 = query_domains.len() as u16;
    query.extend_from_slice(&q_count.to_be_bytes());

    let a_count: u16 = 0;
    query.extend_from_slice(&a_count.to_be_bytes());

    let ns_count: u16 = 0;
    query.extend_from_slice(&ns_count.to_be_bytes());

    let ar_count: u16 = 0;
    query.extend_from_slice(&ar_count.to_be_bytes());

    let mut questions: Vec<u8> = query_domains
        .into_iter()
        .map(|domain| build_question(domain))
        .flatten()
        .collect();
    query.append(&mut questions);

    query
}

#[test]
fn fail_on_empty_message() {
    let result = parse_packet(Span::new(&[]));
    assert!(result.is_err()); // TODO test more carefully
}

#[test]
fn can_parse_heading() {
    let query = build_query(Vec::new());
    let (_, packet) = parse_packet(Span::new(&query)).expect("Packet should parse");

    assert_eq!(
        packet.header,
        Header {
            id: 4660,
            flags: 256,
            q_count: 0,
            a_count: 0,
            ns_count: 0,
            ar_count: 0
        }
    );
}

#[test]
fn can_parse_single_question() {
    let query = build_query(vec!["www.google.com".to_string()]);
    let (_, packet) = parse_packet(Span::new(&query)).expect("Packet should parse");

    assert_eq!(
        packet.header,
        Header {
            id: 4660,
            flags: 256,
            q_count: 1,
            a_count: 0,
            ns_count: 0,
            ar_count: 0
        }
    );

    assert_eq!(packet.questions.len(), 1);
    assert_eq!(
        packet.questions[0],
        Question {
            labels: Name::Labels {
                labels: vec!["www".to_string(), "google".to_string(), "com".to_string()],
                offset: 12
            },
            q_type: 1,
            q_class: 1
        }
    );
}

#[test]
fn can_parse_multiple_questions() {
    let query = build_query(vec![
        "www.google.com".to_string(),
        "wow.i.love.dns".to_string(),
    ]);
    let (_, packet) = parse_packet(Span::new(&query)).expect("Packet should parse");

    assert_eq!(
        packet.header,
        Header {
            id: 4660,
            flags: 256,
            q_count: 2,
            a_count: 0,
            ns_count: 0,
            ar_count: 0
        }
    );

    assert_eq!(packet.questions.len(), 2);
    assert_eq!(
        packet.questions[0],
        Question {
            labels: Name::Labels {
                labels: vec!["www".to_string(), "google".to_string(), "com".to_string()],
                offset: 12
            },
            q_type: 1,
            q_class: 1
        }
    );

    assert_eq!(
        packet.questions[1],
        Question {
            labels: Name::Labels {
                labels: vec![
                    "wow".to_string(),
                    "i".to_string(),
                    "love".to_string(),
                    "dns".to_string()
                ],
                offset: 32
            },
            q_type: 1,
            q_class: 1
        }
    );
}

// TODO once I have better error handling, test more aggressively (e.g. q_count doesn't match the
// number of questions, check on the _type_ of error message we get)
