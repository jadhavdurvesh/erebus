//! Strict, bounded DNS wire-format parser.
//!
//! The parser handles standard labels and compression pointers and preserves
//! unknown resource-record payloads. It deliberately rejects malformed,
//! cyclic, forward-pointing, or over-limit encodings.

use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_message_bytes: usize,
    pub max_questions: usize,
    pub max_records: usize,
    pub max_compression_jumps: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 4096,
            max_questions: 16,
            max_records: 256,
            max_compression_jumps: 32,
        }
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum DnsParseError {
    #[error("DNS message is shorter than the 12-byte header")]
    TruncatedHeader,
    #[error("DNS message exceeds configured size limit")]
    MessageTooLarge,
    #[error("DNS message is truncated at byte {0}")]
    Truncated(usize),
    #[error("DNS section count exceeds configured limit")]
    CountLimitExceeded,
    #[error("invalid DNS label encoding at byte {0}")]
    InvalidLabel(usize),
    #[error("DNS label is not printable ASCII at byte {0}")]
    NonAsciiLabel(usize),
    #[error("expanded DNS name exceeds 255 wire bytes")]
    NameTooLong,
    #[error("DNS compression pointer is outside the packet")]
    PointerOutOfBounds,
    #[error("DNS compression pointer must point backwards")]
    ForwardPointer,
    #[error("DNS compression pointer loop detected")]
    CompressionLoop,
    #[error("DNS compression chain exceeds configured limit")]
    TooManyCompressionJumps,
    #[error("invalid resource-record length for type {0}")]
    InvalidRecordLength(u16),
    #[error("trailing bytes remain after DNS sections")]
    TrailingData,
    #[error("DNS message contains an invalid label or domain name")]
    InvalidDomainName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn is_response(self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    pub fn truncated(self) -> bool {
        self.flags & 0x0200 != 0
    }

    pub fn recursion_desired(self) -> bool {
        self.flags & 0x0100 != 0
    }

    pub fn recursion_available(self) -> bool {
        self.flags & 0x0080 != 0
    }

    pub fn authenticated_data(self) -> bool {
        self.flags & 0x0020 != 0
    }

    pub fn checking_disabled(self) -> bool {
        self.flags & 0x0010 != 0
    }

    pub fn response_code(self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    pub fn authoritative(self) -> bool {
        self.flags & 0x0400 != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    /// Lowercase ASCII presentation name; the root is represented as ".".
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Opt(Vec<u8>),
    Unknown(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

impl DnsRecord {
    pub fn is_opt(&self) -> bool {
        self.rr_type == 41
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn parse(bytes: &[u8]) -> Result<Self, DnsParseError> {
        Self::parse_with_limits(bytes, ParseLimits::default())
    }

    pub fn parse_with_limits(bytes: &[u8], limits: ParseLimits) -> Result<Self, DnsParseError> {
        if bytes.len() < 12 {
            return Err(DnsParseError::TruncatedHeader);
        }
        if bytes.len() > limits.max_message_bytes {
            return Err(DnsParseError::MessageTooLarge);
        }

        let header = DnsHeader {
            id: read_u16(bytes, 0)?,
            flags: read_u16(bytes, 2)?,
            question_count: read_u16(bytes, 4)?,
            answer_count: read_u16(bytes, 6)?,
            authority_count: read_u16(bytes, 8)?,
            additional_count: read_u16(bytes, 10)?,
        };

        let qd = usize::from(header.question_count);
        let an = usize::from(header.answer_count);
        let ns = usize::from(header.authority_count);
        let ar = usize::from(header.additional_count);

        if qd > limits.max_questions
            || an
                .checked_add(ns)
                .and_then(|count| count.checked_add(ar))
                .map_or(true, |count| count > limits.max_records)
        {
            return Err(DnsParseError::CountLimitExceeded);
        }

        let mut cursor = 12;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let name = read_name(bytes, &mut cursor, limits.max_compression_jumps)?;
            let qtype = read_u16(bytes, cursor)?;
            let qclass = read_u16(bytes, cursor + 2)?;
            cursor += 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        let answers = parse_records(bytes, &mut cursor, an, limits)?;
        let authorities = parse_records(bytes, &mut cursor, ns, limits)?;
        let additionals = parse_records(bytes, &mut cursor, ar, limits)?;

        if cursor != bytes.len() {
            return Err(DnsParseError::TrailingData);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn single_question(&self) -> Option<&DnsQuestion> {
        (self.questions.len() == 1).then(|| &self.questions[0])
    }

    pub fn is_query(&self) -> bool {
        !self.header.is_response()
    }

    pub fn is_response(&self) -> bool {
        self.header.is_response()
    }
}

fn parse_records(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    limits: ParseLimits,
) -> Result<Vec<DnsRecord>, DnsParseError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_name(bytes, cursor, limits.max_compression_jumps)?;
        let rr_type = read_u16(bytes, *cursor)?;
        let class = read_u16(bytes, *cursor + 2)?;
        let ttl = read_u32(bytes, *cursor + 4)?;
        let rdlength = usize::from(read_u16(bytes, *cursor + 8)?);
        *cursor += 10;

        let start = *cursor;
        let end = start
            .checked_add(rdlength)
            .filter(|end| *end <= bytes.len())
            .ok_or(DnsParseError::Truncated(start))?;

        let data = parse_rdata(bytes, start, end, rr_type, limits)?;
        *cursor = end;
        records.push(DnsRecord {
            name,
            rr_type,
            class,
            ttl,
            data,
        });
    }
    Ok(records)
}

fn parse_rdata(
    bytes: &[u8],
    start: usize,
    end: usize,
    rr_type: u16,
    limits: ParseLimits,
) -> Result<DnsRecordData, DnsParseError> {
    let length = end - start;
    match rr_type {
        1 if length == 4 => Ok(DnsRecordData::A(Ipv4Addr::new(
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ))),
        28 if length == 16 => {
            let octets: [u8; 16] = bytes[start..end]
                .try_into()
                .map_err(|_| DnsParseError::InvalidRecordLength(rr_type))?;
            Ok(DnsRecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        1 | 28 => Err(DnsParseError::InvalidRecordLength(rr_type)),
        2 | 5 | 12 => {
            let mut cursor = start;
            let name = read_name(bytes, &mut cursor, limits.max_compression_jumps)?;
            if cursor != end {
                return Err(DnsParseError::InvalidRecordLength(rr_type));
            }
            Ok(DnsRecordData::Name(name))
        }
        15 => {
            if length < 3 {
                return Err(DnsParseError::InvalidRecordLength(rr_type));
            }
            let preference = read_u16(bytes, start)?;
            let mut cursor = start + 2;
            let exchange = read_name(bytes, &mut cursor, limits.max_compression_jumps)?;
            if cursor != end {
                return Err(DnsParseError::InvalidRecordLength(rr_type));
            }
            Ok(DnsRecordData::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            let mut cursor = start;
            let mut strings = Vec::new();
            while cursor < end {
                let size = usize::from(bytes[cursor]);
                cursor += 1;
                let string_end = cursor
                    .checked_add(size)
                    .filter(|value| *value <= end)
                    .ok_or(DnsParseError::InvalidRecordLength(rr_type))?;
                let value = std::str::from_utf8(&bytes[cursor..string_end])
                    .map_err(|_| DnsParseError::InvalidRecordLength(rr_type))?;
                strings.push(value.to_owned());
                cursor = string_end;
            }
            Ok(DnsRecordData::Txt(strings))
        }
        33 => {
            if length < 7 {
                return Err(DnsParseError::InvalidRecordLength(rr_type));
            }
            let priority = read_u16(bytes, start)?;
            let weight = read_u16(bytes, start + 2)?;
            let port = read_u16(bytes, start + 4)?;
            let mut cursor = start + 6;
            let target = read_name(bytes, &mut cursor, limits.max_compression_jumps)?;
            if cursor != end {
                return Err(DnsParseError::InvalidRecordLength(rr_type));
            }
            Ok(DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        41 => Ok(DnsRecordData::Opt(bytes[start..end].to_vec())),
        _ => Ok(DnsRecordData::Unknown(bytes[start..end].to_vec())),
    }
}

/// Read a possibly compressed DNS name and advance cursor by the number of
/// bytes consumed at the original location (not the pointer target).
fn read_name(bytes: &[u8], cursor: &mut usize, max_jumps: usize) -> Result<String, DnsParseError> {
    let mut position = *cursor;
    let mut original_end = None;
    let mut labels = Vec::new();
    let mut expanded_len = 1usize;
    let mut jumps = 0usize;
    let mut visited = Vec::new();

    loop {
        let length = *bytes
            .get(position)
            .ok_or(DnsParseError::Truncated(position))?;

        match length & 0xc0 {
            0xc0 => {
                let second = *bytes
                    .get(position + 1)
                    .ok_or(DnsParseError::Truncated(position + 1))?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
                if target >= bytes.len() {
                    return Err(DnsParseError::PointerOutOfBounds);
                }
                if target >= position {
                    return Err(DnsParseError::ForwardPointer);
                }
                if visited.contains(&target) {
                    return Err(DnsParseError::CompressionLoop);
                }
                jumps += 1;
                if jumps > max_jumps {
                    return Err(DnsParseError::TooManyCompressionJumps);
                }
                visited.push(target);
                original_end.get_or_insert(position + 2);
                position = target;
            }
            0x00 => {
                position += 1;
                if length == 0 {
                    *cursor = original_end.unwrap_or(position);
                    if labels.is_empty() {
                        return Ok(".".to_owned());
                    }
                    return Ok(labels.join("."));
                }

                let size = usize::from(length);
                let end = position
                    .checked_add(size)
                    .filter(|end| *end <= bytes.len())
                    .ok_or(DnsParseError::Truncated(position))?;

                expanded_len = expanded_len
                    .checked_add(size + 1)
                    .filter(|value| *value <= 255)
                    .ok_or(DnsParseError::NameTooLong)?;

                let label = &bytes[position..end];
                if label
                    .iter()
                    .any(|byte| !(0x21..=0x7e).contains(byte) || *byte == b'.')
                {
                    return Err(DnsParseError::NonAsciiLabel(position));
                }
                let text =
                    std::str::from_utf8(label).map_err(|_| DnsParseError::InvalidDomainName)?;
                labels.push(text.to_ascii_lowercase());
                position = end;
            }
            _ => return Err(DnsParseError::InvalidLabel(position)),
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(DnsParseError::Truncated(offset))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DnsParseError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(DnsParseError::Truncated(offset))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_packet() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, // id, standard query with RD
            0x00, 0x01, 0x00, 0x00, // QDCOUNT, ANCOUNT
            0x00, 0x00, 0x00, 0x00, // NSCOUNT, ARCOUNT
        ];
        packet.extend_from_slice(&[
            7, b'E', b'x', b'A', b'M', b'P', b'L', b'E', 3, b'C', b'O', b'M', 0, 0, 1, 0, 1,
        ]);
        packet
    }

    #[test]
    fn parses_case_insensitive_query_name() {
        let message = DnsMessage::parse(&query_packet()).unwrap();
        assert!(message.is_query());
        assert_eq!(message.header.id, 0x1234);
        assert_eq!(message.questions[0].name, "example.com");
        assert_eq!(message.questions[0].qtype, 1);
    }

    #[test]
    fn parses_compressed_a_record() {
        let mut packet = query_packet();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 1;
        packet.extend_from_slice(&[
            0xc0, 0x0c, // name pointer to question name
            0, 1, 0, 1, // A, IN
            0, 0, 0, 60, // TTL
            0, 4, 203, 0, 113, 7,
        ]);

        let message = DnsMessage::parse(&packet).unwrap();
        assert!(message.is_response());
        assert_eq!(message.answers[0].name, "example.com");
        assert_eq!(
            message.answers[0].data,
            DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(message.answers[0].ttl, 60);
    }

    #[test]
    fn rejects_truncated_and_over_limit_packets() {
        assert_eq!(
            DnsMessage::parse(&[0; 11]),
            Err(DnsParseError::TruncatedHeader)
        );
        let packet = query_packet();
        assert_eq!(
            DnsMessage::parse_with_limits(
                &packet,
                ParseLimits {
                    max_message_bytes: 12,
                    ..ParseLimits::default()
                }
            ),
            Err(DnsParseError::MessageTooLarge)
        );
    }

    #[test]
    fn rejects_compression_self_reference() {
        let mut packet = query_packet();
        packet[12] = 0xc0;
        packet[13] = 0x0c;
        assert_eq!(
            DnsMessage::parse(&packet),
            Err(DnsParseError::ForwardPointer)
        );
    }

    #[test]
    fn preserves_unknown_record_data() {
        let mut packet = query_packet();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0xfd, 0xe8, 0, 1, 0, 0, 0, 5, 0, 3, 1, 2, 3]);

        let message = DnsMessage::parse(&packet).unwrap();
        assert_eq!(
            message.answers[0].data,
            DnsRecordData::Unknown(vec![1, 2, 3])
        );
    }

    #[test]
    fn root_name_is_supported() {
        let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        let message = DnsMessage::parse(&packet).unwrap();
        assert_eq!(message.questions[0].name, ".");
        packet.push(0);
        assert_eq!(DnsMessage::parse(&packet), Err(DnsParseError::TrailingData));
    }
}
