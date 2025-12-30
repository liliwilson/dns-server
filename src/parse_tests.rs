use std::fs;

use std::net::Ipv4Addr;

#[cfg(test)]
use crate::packet::RecordData;
#[cfg(test)]
use crate::packet::RecordType;
#[cfg(test)]
use crate::parse::*;
#[cfg(test)]
use nom::error::ErrorKind;

#[cfg(test)]
fn build_literal_resource_name(target_domain: &Vec<String>, include_terminator: bool) -> Vec<u8> {
    let mut results: Vec<u8> = target_domain
        .iter()
        .map(|label| {
            let label_data: Vec<u8> = label.bytes().collect();
            std::iter::once(label_data.len() as u8).chain(label_data)
        })
        .flatten()
        .collect();

    if include_terminator {
        results.push(0); // root terminate
    }

    results
}

#[cfg(test)]
fn build_resource_name_from_offset(offset: u16) -> Vec<u8> {
    let offset = offset | (COMPRESSION_MASK as u16) << 8;
    offset.to_be_bytes().to_vec()
}

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
    let result = parse_packet(Span::new_extra(&[], ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::Nom(_, ErrorKind::Eof)) => {}
        other => panic!("Expected Eof error, got {:?}", other),
    }
}

#[test]
fn can_parse_heading() {
    let query = build_query(Vec::new());
    let (_, packet) =
        parse_packet(Span::new_extra(&query, ParseContext::new())).expect("Packet should parse");

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
fn fail_on_short_header() {
    let query = build_query(Vec::new());
    let result = parse_packet(Span::new_extra(
        &query[0..query.len() - 2],
        ParseContext::new(),
    ));

    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::Nom(_, ErrorKind::Eof)) => {}
        other => panic!("Expected Eof error, got {:?}", other),
    }
}

#[test]
fn can_parse_single_question() {
    let query = build_query(vec!["www.google.com".to_string()]);
    let (_, packet) =
        parse_packet(Span::new_extra(&query, ParseContext::new())).expect("Packet should parse");

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
            labels: vec!["www".to_string(), "google".to_string(), "com".to_string()].into(),
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
    let (_, packet) =
        parse_packet(Span::new_extra(&query, ParseContext::new())).expect("Packet should parse");

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
            labels: vec!["www".to_string(), "google".to_string(), "com".to_string()].into(),
            q_type: 1,
            q_class: 1
        }
    );

    assert_eq!(
        packet.questions[1],
        Question {
            labels: vec![
                "wow".to_string(),
                "i".to_string(),
                "love".to_string(),
                "dns".to_string()
            ]
            .into(),
            q_type: 1,
            q_class: 1
        }
    );
}

#[test]
fn fail_on_not_enough_questions() {
    // Build a packet that claims q_count=2 but only has 1 question
    let mut packet = Vec::new();

    let id: u16 = 0x1234;
    packet.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x0100;
    packet.extend_from_slice(&flags.to_be_bytes());
    let q_count: u16 = 2; // Claims 2 questions
    packet.extend_from_slice(&q_count.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // a_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ns_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ar_count

    // Only add 1 question
    packet.append(&mut build_question("www.google.com".to_string()));

    let result = parse_packet(Span::new_extra(&packet, ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::Nom(_, ErrorKind::Eof)) => {}
        other => panic!("Expected Eof error, got {:?}", other),
    }
}

#[test]
fn can_parse_literal_resource_name() {
    let target_domain = vec!["www".to_string(), "google".to_string(), "com".to_string()];
    let input = build_literal_resource_name(&target_domain, true);

    let (_, result) = parse_resource_name(Span::new_extra(&input, ParseContext::new()))
        .expect("Resource name should parse");
    assert_eq!(result, target_domain.into());
}

#[test]
fn can_parse_compressed_resource_name_with_offset() {
    let target_domain = vec!["www".to_string(), "google".to_string(), "com".to_string()];

    let mut literal_name = build_literal_resource_name(&target_domain, true);
    // this points to the entire literal, which should be in the cache at offset 0
    let mut exact_offset_name = build_resource_name_from_offset(0);
    // this points to a suffix of a literal
    let mut middle_offset_name = build_resource_name_from_offset(4);
    // make a literal that's not terminated, and use an offest for the end that's just the `com`
    let mut mixed_literal =
        build_literal_resource_name(&vec!["hello".to_string(), "world".to_string()], false);
    let mut mixed_literal_offset = build_resource_name_from_offset(11);

    let mut input = Vec::new();
    input.append(&mut literal_name);
    input.append(&mut exact_offset_name);
    input.append(&mut middle_offset_name);
    input.append(&mut mixed_literal);
    input.append(&mut mixed_literal_offset);

    // get www.google.com into the label cache at offset 0
    let (remaining, _) = parse_resource_name(Span::new_extra(&input, ParseContext::new()))
        .expect("Resource name should parse");

    let (remaining, result) = parse_resource_name(remaining).expect("Resource name should parse");
    assert_eq!(result, target_domain.into());

    let (remaining, result) = parse_resource_name(remaining).expect("Resource name should parse");
    assert_eq!(result, vec!["google".to_string(), "com".to_string()].into());

    let (_, result) = parse_resource_name(remaining).expect("Resource name should parse");
    assert_eq!(
        result,
        vec!["hello".to_string(), "world".to_string(), "com".to_string()].into()
    );
}

#[test]
fn fail_parse_resource_name_with_invalid_offset() {
    let target_domain = vec!["www".to_string(), "google".to_string(), "com".to_string()];
    let mut literal_name = build_literal_resource_name(&target_domain, true);
    let mut exact_offset_name = build_resource_name_from_offset(100); // Invalid offset

    let mut input = Vec::new();
    input.append(&mut literal_name);
    input.append(&mut exact_offset_name);

    // get www.google.com into the label cache at offset 0
    let (remaining, _) = parse_resource_name(Span::new_extra(&input, ParseContext::new()))
        .expect("Resource name should parse");

    let result = parse_resource_name(remaining);
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Failure(DnsParseError::InvalidCompressionOffset { offset, .. }) => {
            assert_eq!(offset, 100);
        }
        other => panic!("Expected InvalidCompressionOffset, got {:?}", other),
    }
}

#[cfg(test)]
fn build_resource(name: &Vec<String>, r_type: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut resource = build_literal_resource_name(name, true);
    resource.extend_from_slice(&r_type.to_be_bytes());
    resource.extend_from_slice(&class.to_be_bytes());
    resource.extend_from_slice(&ttl.to_be_bytes());
    resource.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resource.extend_from_slice(rdata);
    resource
}

#[cfg(test)]
fn build_answer_packet(answer_resources: Vec<Vec<u8>>) -> Vec<u8> {
    let mut packet = Vec::new();

    let id: u16 = 0x1234;
    packet.extend_from_slice(&id.to_be_bytes());

    let flags: u16 = 0x8180; // response, recursion available
    packet.extend_from_slice(&flags.to_be_bytes());

    let q_count: u16 = 0;
    packet.extend_from_slice(&q_count.to_be_bytes());

    let a_count: u16 = answer_resources.len() as u16;
    packet.extend_from_slice(&a_count.to_be_bytes());

    let ns_count: u16 = 0;
    packet.extend_from_slice(&ns_count.to_be_bytes());

    let ar_count: u16 = 0;
    packet.extend_from_slice(&ar_count.to_be_bytes());

    for resource in answer_resources {
        packet.extend_from_slice(&resource);
    }

    packet
}

#[test]
fn can_parse_a_record_data() {
    let domain = vec!["example".to_string(), "com".to_string()];
    let ipv4_addr: [u8; 4] = [93, 184, 216, 34]; // 93.184.216.34
    let resource = build_resource(&domain, 1, 1, 300, &ipv4_addr);
    let packet = build_answer_packet(vec![resource]);

    let (_, result) =
        parse_packet(Span::new_extra(&packet, ParseContext::new())).expect("Packet should parse");

    assert_eq!(result.answers.len(), 1);
    assert_eq!(result.answers[0].r_type, RecordType::A);
    assert_eq!(result.answers[0].rdlength, 4);
    assert_eq!(
        result.answers[0].rdata,
        RecordData::AddressData(Ipv4Addr::from(ipv4_addr).into())
    );
}

#[test]
fn can_parse_ns_record_data() {
    let domain = vec!["example".to_string(), "com".to_string()];
    let ns_domain = vec!["ns1".to_string(), "example".to_string(), "com".to_string()];
    let ns_rdata = build_literal_resource_name(&ns_domain, true);
    let resource = build_resource(&domain, 2, 1, 300, &ns_rdata);
    let packet = build_answer_packet(vec![resource]);

    let (_, result) =
        parse_packet(Span::new_extra(&packet, ParseContext::new())).expect("Packet should parse");

    assert_eq!(result.answers.len(), 1);
    assert_eq!(result.answers[0].r_type, RecordType::NS);
    assert_eq!(
        result.answers[0].rdata,
        RecordData::NameServerData(ns_domain.into())
    );
}

#[test]
fn fail_parse_record_data_with_truncated_rdata() {
    // rdlength says 4 but only 2 bytes provided - runs out of data
    let domain = vec!["example".to_string(), "com".to_string()];
    let bad_rdata: [u8; 2] = [93, 184];

    let mut resource = build_literal_resource_name(&domain, true);
    resource.extend_from_slice(&1u16.to_be_bytes()); // type A
    resource.extend_from_slice(&1u16.to_be_bytes()); // class IN
    resource.extend_from_slice(&300u32.to_be_bytes()); // ttl
    resource.extend_from_slice(&4u16.to_be_bytes()); // rdlength says 4
    resource.extend_from_slice(&bad_rdata); // but only 2 bytes provided

    let packet = build_answer_packet(vec![resource]);

    let result = parse_packet(Span::new_extra(&packet, ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::Nom(_, ErrorKind::Eof)) => {}
        other => panic!("Expected Eof error, got {:?}", other),
    }
}

#[test]
fn fail_parse_record_data_with_wrong_rdlength() {
    // rdlength says 3 but A record requires exactly 4 - verify fails
    // We provide 4 bytes so be_u32 succeeds, but rdlength=3 makes verify fail
    let domain = vec!["example".to_string(), "com".to_string()];
    let rdata: [u8; 4] = [93, 184, 216, 34];

    let mut resource = build_literal_resource_name(&domain, true);
    resource.extend_from_slice(&1u16.to_be_bytes()); // type A
    resource.extend_from_slice(&1u16.to_be_bytes()); // class IN
    resource.extend_from_slice(&300u32.to_be_bytes()); // ttl
    resource.extend_from_slice(&3u16.to_be_bytes()); // rdlength says 3 (wrong for A record)
    resource.extend_from_slice(&rdata); // 4 bytes provided so be_u32 succeeds

    let packet = build_answer_packet(vec![resource]);

    let result = parse_packet(Span::new_extra(&packet, ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::InvalidRdlength {
            expected: 4,
            actual: 3,
            record_type: RecordType::A,
            ..
        })
        | nom::Err::Failure(DnsParseError::InvalidRdlength {
            expected: 4,
            actual: 3,
            record_type: RecordType::A,
            ..
        }) => {}
        other => panic!("Expected InvalidRdlength, got {:?}", other),
    }
}

#[test]
fn can_build_packet_without_compression() {
    let file = fs::read("./test_data/dns_query.bin").expect("should be able to read the file");
    let (_, packet) =
        parse_packet(Span::new_extra(&file, ParseContext::new())).expect("Packet should parse");

    let mut builder = PacketBuilder::new();
    let query = builder.build(packet);

    assert_eq!(query, file);
}

#[test]
fn can_build_packet_with_compression() {
    let file = fs::read("./test_data/dns_answer.bin").expect("should be able to read the file");
    let (_, packet) =
        parse_packet(Span::new_extra(&file, ParseContext::new())).expect("Packet should parse");

    let mut builder = PacketBuilder::new();
    let query = builder.build(packet);

    assert_eq!(query, file);
}

#[test]
fn fail_on_invalid_utf8_label() {
    // Build a packet with invalid UTF-8 in the domain label
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // flags
    packet.extend_from_slice(&1u16.to_be_bytes()); // q_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // a_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ns_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ar_count

    // Question with invalid UTF-8 label
    packet.push(3); // label length
    packet.extend_from_slice(&[0xFF, 0xFE, 0x80]); // invalid UTF-8 bytes
    packet.push(0); // terminate
    packet.extend_from_slice(&1u16.to_be_bytes()); // type A
    packet.extend_from_slice(&1u16.to_be_bytes()); // class IN

    let result = parse_packet(Span::new_extra(&packet, ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::InvalidUtf8Label { .. }) => {}
        other => panic!("Expected InvalidUtf8Label, got {:?}", other),
    }
}

#[test]
fn fail_on_truncated_question() {
    // Build packet with question that's cut off mid-label
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // flags
    packet.extend_from_slice(&1u16.to_be_bytes()); // q_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // a_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ns_count
    packet.extend_from_slice(&0u16.to_be_bytes()); // ar_count

    // Truncated question - label says 10 bytes but only 3 provided
    packet.push(10); // label length claims 10
    packet.extend_from_slice(b"www"); // only 3 bytes

    let result = parse_packet(Span::new_extra(&packet, ParseContext::new()));
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        nom::Err::Error(DnsParseError::Nom(_, ErrorKind::Eof)) => {}
        other => panic!("Expected Eof error, got {:?}", other),
    }
}
