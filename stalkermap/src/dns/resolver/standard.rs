//! # Stalkermap DNS Resolver – Internal DNSMessage
//!
//! This module defines the **internal representation** of DNS messages for the Stalkermap resolver.
//! It provides the building blocks for constructing, encoding, and parsing DNS messages in a
//! controlled way, suitable for internal use by transport and decoder layers.
//!
//! Key features include:
//! - Fully structured DNS message representation with `DnsMessage`.
//! - Header, question, answer, authority, and additional sections.
//! - Encoding and decoding DNS header flags via `DnsHeaderFlags`.
//! - Support for multiple record types (`RecordType`) including A, MX, TXT, CNAME, etc.
//! - ID generation for queries (`generate_id()`).
//! - Query encoding with optional name compression via `MessageCompressor`.
//!
//! ## Sections
//!
//! - **HeaderSection**: Contains the message ID, flags, and counts of each section.
//! - **DnsHeaderFlags**: Represents the 16-bit flags field and supports encoding/decoding.
//! - **QuestionSection**: Holds the query name, type, and class.
//! - **AnswerSection / AuthoritySection / AdditionalSection**: Represent RRs (Resource Records) with owner name, type, class, TTL, and RDATA.
//! - **RecordType**: Enum of supported DNS record types with encoding helper.
//!
//! ## Usage
//!
//! The internal API is intended to be used with lower-level transport and parser layers.
//! For example, you can construct a query and encode it for sending over UDP/TCP:
//!
//! ```rust,ignore
//! let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);
//! let query_bytes = msg.encode_query();
//! ```
//!
//! After receiving a response, the message can be parsed into the same `DnsMessage` structure
//! to inspect answers, authorities, or additional sections.
use crate::dns::compressor::{DecompressorErrors, MessageCompressor};
use std::{collections::HashMap, error::Error, fmt::Display, net::Ipv4Addr};

mod internal {
    use rand::Rng;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    /// Generates a random 16-bit ID for a DNS query.
    pub(crate) fn generate_id() -> u16 {
        let mut thread_rng = rand::rng();
        let mut rng = SmallRng::from_rng(&mut thread_rng);

        rng.random::<u16>()
    }
}

/// Represents a full DNS message, including header and all four sections.
///
/// This struct is fully internal: you can construct it manually, populate fields,
/// and encode it using helper functions or custom routines.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    pub header: HeaderSection,
    // The question for the name server
    pub question: QuestionSection,
    // RRs answering the question
    pub answer: Vec<AnswerSection>,
    // RRs pointing toward an authority
    pub authority: Vec<AuthoritySection>,
    // RRs holding additional information
    pub additional: Vec<AdditionalSection>,
}

impl DnsMessage {
    /// Creates a new standard query message and returns the `id` used in the query.
    ///
    /// # Arguments
    /// * `target` - The domain name to query.
    /// * `record_type` - Type of record (A, MX, TXT, etc.).
    /// * `query_type` - DNS operation code (Standard, Inverse, or ServerStatus).
    pub(crate) fn new_query(
        target: &str,
        record_type: RecordType,
        query_type: OpCodeOptions,
    ) -> (DnsMessage, u16) {
        let id = internal::generate_id();
        (
            DnsMessage {
                header: HeaderSection {
                    id, //random u16 number
                    flags: DnsHeaderFlags {
                        qr: false,
                        opcode: query_type as u8,
                        aa: false,
                        tc: false,
                        rd: true,
                        ra: false,
                        z: 0,
                        rcode: 0,
                    }
                    .to_u16(),
                    qd_count: 1,
                    an_count: 0,
                    ns_count: 0,
                    ar_count: 0,
                },
                question: QuestionSection {
                    name: target.to_string(),
                    record_type: record_type as u16,
                    class: 1,
                },
                answer: Vec::new(),
                authority: Vec::new(),
                additional: Vec::new(),
            },
            id,
        )
    }

    /// Encodes the DNS query into bytes for sending over the network.
    ///
    /// This uses RFC1035-compliant compression on domain names via `MessageCompressor`.
    pub(crate) fn encode_query(&self) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();
        let mut pointer_map: HashMap<String, usize> = HashMap::new();

        message.extend_from_slice(&self.header.to_bytes());

        MessageCompressor::compress(&self.question.name, &mut message, &mut pointer_map).unwrap();
        message.extend_from_slice(&self.question.record_type.to_be_bytes());
        message.extend_from_slice(&self.question.class.to_be_bytes());
        message
    }

    pub(crate) fn decode_query(buf: &[u8]) -> Result<DnsMessage, DecodeQueryErrors> {
        //header
        if buf.len() < 12 {
            return Err(DecodeQueryErrors::InvalidBufferSize);
        }

        let header = HeaderSection {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qd_count: u16::from_be_bytes([buf[4], buf[5]]),
            an_count: u16::from_be_bytes([buf[6], buf[7]]),
            ns_count: u16::from_be_bytes([buf[8], buf[9]]),
            ar_count: u16::from_be_bytes([buf[10], buf[11]]),
        };
        let mut offset: usize = 12;

        if header.qd_count > 1 {
            return Err(DecodeQueryErrors::MultipleQuestionSections);
        }

        //question
        let qname = match MessageCompressor::decompress_name(buf, &mut offset) {
            Ok(s) => s,
            Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
        };

        if offset + 4 > buf.len() {
            return Err(DecodeQueryErrors::InvalidBufferSize);
        }

        let qrecord_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;

        let question = QuestionSection {
            name: qname,
            record_type: qrecord_type,
            class: qclass,
        };

        //answer
        let mut answer: Vec<AnswerSection> = Vec::new();
        for _ in 0..header.an_count {
            let aowner_name = match MessageCompressor::decompress_name(buf, &mut offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            };

            if offset + 10 > buf.len() {
                return Err(DecodeQueryErrors::InvalidBufferSize);
            }

            let arecord_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let aclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let attl = i32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            let ard_length = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]);
            offset += 10;

            let temp_l = offset + ard_length as usize;
            let ar_data = &buf[offset..temp_l];

            // check type of rr and parse it as so
            let record_data: RecordData =
                decode_rdata(arecord_type, buf, &mut offset, ar_data, ard_length)?;

            //offset += ard_length as usize;

            answer.push(AnswerSection {
                owner_name: aowner_name,
                record_type: arecord_type,
                class: aclass,
                ttl: attl,
                rd_length: ard_length,
                r_data: record_data,
            });
        }

        //authority
        let mut authority: Vec<AuthoritySection> = Vec::new();

        for _ in 0..header.ns_count {
            let nowner_name = match MessageCompressor::decompress_name(buf, &mut offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            };

            if offset + 10 > buf.len() {
                return Err(DecodeQueryErrors::InvalidBufferSize);
            }

            let nrecord_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let nclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let nttl = i32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            let nrd_length = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]);
            offset += 10;

            let temp_l = offset + nrd_length as usize;
            let nr_data = &buf[offset..temp_l];

            let record_data: RecordData =
                decode_rdata(nrecord_type, buf, &mut offset, nr_data, nrd_length)?;

            authority.push(AuthoritySection {
                owner_name: nowner_name,
                record_type: nrecord_type,
                class: nclass,
                ttl: nttl,
                rd_length: nrd_length,
                r_data: record_data,
            });
        }

        //additional
        let mut additional: Vec<AdditionalSection> = Vec::new();

        for _ in 0..header.ar_count {
            let aowner_name = match MessageCompressor::decompress_name(buf, &mut offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            };

            if offset + 10 > buf.len() {
                return Err(DecodeQueryErrors::InvalidBufferSize);
            }

            let arecord_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let aclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let attl = i32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            let ard_length = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]);
            offset += 10;

            let temp_l = offset + ard_length as usize;
            let ar_data = &buf[offset..temp_l];

            let record_data: RecordData =
                decode_rdata(arecord_type, buf, &mut offset, ar_data, ard_length)?;

            additional.push(AdditionalSection {
                owner_name: aowner_name,
                record_type: arecord_type,
                class: aclass,
                ttl: attl,
                rd_length: ard_length,
                r_data: record_data,
            });
        }

        Ok(DnsMessage {
            header,
            question,
            answer,
            authority,
            additional,
        })
    }
}

fn decode_rdata(
    arecord_type: u16,
    buf: &[u8],
    offset: &mut usize,
    ar_data: &[u8],
    ard_length: u16,
) -> Result<RecordData, DecodeQueryErrors> {
    match arecord_type {
        TYPE_A => {
            if ar_data.len() == 4 {
                let ip: Ipv4Addr = Ipv4Addr::new(ar_data[0], ar_data[1], ar_data[2], ar_data[3]);

                *offset += ard_length as usize;
                Ok(RecordData::A(ip))
            } else {
                *offset += ard_length as usize;
                Ok(RecordData::Unknown(TYPE_A, ar_data.to_vec()))
            }
        }
        TYPE_NS => match MessageCompressor::decompress_name(buf, offset) {
            Ok(s) => Ok(RecordData::Ns(s)),
            Err(e) => Err(DecodeQueryErrors::DecompressorError(e)),
        },
        TYPE_CNAME | TYPE_PTR => match MessageCompressor::decompress_name(buf, offset) {
            Ok(s) => Ok(RecordData::Cname(s)),
            Err(e) => Err(DecodeQueryErrors::DecompressorError(e)),
        },
        TYPE_SOA => Ok(RecordData::Soa {
            mname: match MessageCompressor::decompress_name(buf, offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            },
            rname: match MessageCompressor::decompress_name(buf, offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            },
            serial: u32::from_be_bytes([
                buf[*offset],
                buf[*offset + 1],
                buf[*offset + 2],
                buf[*offset + 3],
            ]),
            refresh: u32::from_be_bytes([
                buf[*offset + 4],
                buf[*offset + 5],
                buf[*offset + 6],
                buf[*offset + 7],
            ]),
            retry: u32::from_be_bytes([
                buf[*offset + 8],
                buf[*offset + 9],
                buf[*offset + 10],
                buf[*offset + 11],
            ]),
            expire: u32::from_be_bytes([
                buf[*offset + 12],
                buf[*offset + 13],
                buf[*offset + 14],
                buf[*offset + 15],
            ]),
            minimum: {
                let val = u32::from_be_bytes([
                    buf[*offset + 16],
                    buf[*offset + 17],
                    buf[*offset + 18],
                    buf[*offset + 19],
                ]);
                *offset += 20;
                val
            },
        }),
        TYPE_WKS => {
            let val = RecordData::Wks {
                adress: Ipv4Addr::new(ar_data[0], ar_data[1], ar_data[2], ar_data[3]),
                protocol: ar_data[4],
                bitmap: ar_data[5..].to_vec(),
            };
            *offset += ard_length as usize;
            Ok(val)
        }
        TYPE_HINFO => {
            let mut texts = Vec::new();
            let mut pos = 0;
            while pos < ar_data.len() {
                let len = ar_data[pos] as usize;
                pos += 1;
                if pos + len <= ar_data.len() {
                    let txt = String::from_utf8_lossy(&ar_data[pos..pos + len]).to_string();
                    texts.push(txt);
                }
                pos += len;
            }

            *offset += ard_length as usize;
            Ok(RecordData::Hinfo {
                cpu: texts[0].to_string(),
                os: texts[1].to_string(),
            })
        }
        TYPE_MINFO => Ok(RecordData::Minfo {
            rmailbx: match MessageCompressor::decompress_name(buf, offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            },
            emailbx: match MessageCompressor::decompress_name(buf, offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            },
        }),
        TYPE_MX => Ok(RecordData::Mx {
            preference: {
                *offset += 2;
                u16::from_be_bytes([ar_data[0], ar_data[1]])
            },
            exchange: match MessageCompressor::decompress_name(buf, offset) {
                Ok(s) => s,
                Err(e) => return Err(DecodeQueryErrors::DecompressorError(e)),
            },
        }),
        TYPE_TXT => {
            let mut texts = Vec::new();
            let mut pos = 0;
            while pos < ar_data.len() {
                let len = ar_data[pos] as usize;
                pos += 1;
                if pos + len <= ar_data.len() {
                    let txt = String::from_utf8_lossy(&ar_data[pos..pos + len]).to_string();
                    texts.push(txt);
                }
                pos += len;
            }

            *offset += ard_length as usize;
            Ok(RecordData::Txt(texts))
        }
        _ => Ok(RecordData::Unknown(arecord_type, ar_data.to_vec())),
    }
}

#[derive(Debug)]
pub enum DecodeQueryErrors {
    InvalidBufferSize,
    MultipleQuestionSections,
    DecompressorError(DecompressorErrors),
}

impl Display for DecodeQueryErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeQueryErrors::InvalidBufferSize => {
                write!(f, "Invalid buffer to decode.")
            }
            DecodeQueryErrors::MultipleQuestionSections => {
                write!(f, "DNS Resolver doesn't support multiple question sections")
            }
            DecodeQueryErrors::DecompressorError(e) => write!(f, "{}", e),
        }
    }
}

impl Error for DecodeQueryErrors {}
/// Represents the header section of a DNS message.
///
/// The header contains an ID, flags, and counts for each section
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeaderSection {
    /// Identifier to match requests and responses.
    pub(crate) id: u16,
    /// Flags and control bits for the DNS message.
    /// Use [`DnsHeaderFlags`]
    pub(crate) flags: u16,
    /// Number of entries in the question section.
    pub(crate) qd_count: u16,
    /// Number of resource records in the answer section.
    pub(crate) an_count: u16,
    /// Number of name server records in the authority section.
    pub(crate) ns_count: u16,
    /// Number of resource records in the additional section.
    pub(crate) ar_count: u16,
}

#[allow(clippy::wrong_self_convention)]
impl HeaderSection {
    /// Converts the header into a 12-byte array suitable for network transmission.
    pub(crate) fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.ar_count.to_be_bytes());
        bytes
    }
}

/// Represents the 16-bit DNS flags field (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DnsHeaderFlags {
    /// Query/Response flag
    pub(crate) qr: bool,
    /// Operation code
    /// Use `OpCodeOptions`
    pub(crate) opcode: u8,
    /// Authoritative Answer
    pub(crate) aa: bool,
    /// Truncation flag
    pub(crate) tc: bool,
    /// Recursion Desired
    pub(crate) rd: bool,
    /// Recursion Available
    pub(crate) ra: bool,
    /// Reserved bits (RFC 1035)
    pub(crate) z: u8,
    /// Response code
    pub(crate) rcode: u8,
}

// 3-15 reserved for future use
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum OpCodeOptions {
    StandardQuery = 0,
    //InverseQuery = 1,
    _ServerStatusRequest = 2,
}

impl DnsHeaderFlags {
    /// Encode the flags into a 16-bit integer.
    pub(crate) fn to_u16(self) -> u16 {
        ((self.qr as u16) << 15)
            | ((self.opcode as u16 & 0b1111) << 11)
            | ((self.aa as u16) << 10)
            | ((self.tc as u16) << 9)
            | ((self.rd as u16) << 8)
            | ((self.ra as u16) << 7)
            | ((self.z as u16 & 0b111) << 4)
            | (self.rcode as u16 & 0b1111)
    }
    /// Decode from a 16-bit integer into structured flags.
    pub(crate) fn _from_u16(value: u16) -> Self {
        Self {
            qr: (value >> 15) & 1 != 0,
            opcode: ((value >> 11) & 0b1111) as u8,
            aa: (value >> 10) & 1 != 0,
            tc: (value >> 9) & 1 != 0,
            rd: (value >> 8) & 1 != 0,
            ra: (value >> 7) & 1 != 0,
            z: ((value >> 4) & 0b111) as u8,
            rcode: (value & 0b1111) as u8,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuestionSection {
    /// The domain name being queried.
    pub name: String,
    /// The type of DNS record being requested (e.g., A, AAAA, MX).
    pub record_type: u16,
    /// The class of the DNS record (usually IN for Internet, or CH for Chaos).
    pub class: u16,
}

/// Represents a single answer record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug, Clone, PartialEq)]
pub struct AnswerSection {
    /// The domain name that owns this record.
    pub owner_name: String,
    /// The type of DNS record (e.g., A, AAAA, CNAME).
    pub record_type: u16,
    /// The class of the DNS record (usually IN).
    pub class: u16,
    /// Time-to-live of the record in seconds.
    pub ttl: i32,
    /// Length of the RDATA field.
    pub rd_length: u16,
    /// The actual resource data (e.g., IP address for A record).
    pub r_data: RecordData,
}

/// Represents a single authority record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthoritySection {
    /// The domain name that owns this record.
    pub owner_name: String,
    /// The type of DNS record.
    pub record_type: u16,
    /// The class of the DNS record.
    pub class: u16,
    /// Time-to-live of the record in seconds.
    pub ttl: i32,
    /// Length of the RDATA field.
    pub rd_length: u16,
    /// The actual resource data (e.g., authoritative name server).
    pub r_data: RecordData,
}

/// Represents a single additional record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalSection {
    /// The domain name that owns this record.
    pub owner_name: String,
    /// The type of DNS record.
    pub record_type: u16,
    /// The class of the DNS record.
    pub class: u16,
    /// Time-to-live of the record in seconds.
    pub ttl: i32,
    /// Length of the RDATA field.
    pub rd_length: u16,
    /// The actual resource data (e.g., additional IP information).
    pub r_data: RecordData,
}

/// TYPE fields are used in resource records.  Note that these types are a subset of QTYPEs.
///
/// Make sure for when using it for the Dns message you encode it like shown below:
///
/// # Example
///
/// ```rust,no_run
/// //use stalkermap::dns::resolver::RecordType;
///
/// //let record_type = RecordType::A.to_bytes();
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RecordType {
    // A host address
    A = 1,
    // An authoritative name server
    Ns = 2,
    // The Canonical name for an alias
    Cname = 5,
    // Marks the start of a zone of authority
    Soa = 6,
    // A well known service description
    Wks = 11,
    // A domain name pointer
    Ptr = 12,
    // Host information
    Hinfo = 13,
    // Mailbox or mail list information
    Minfo = 14,
    // Mail exchange
    Mx = 15,
    // Text strings
    Txt = 16,
    //Aaaa = 28,
    //Srv = 33,
    //Naptr = 35,
    //Https = 65,
    //Caa = 257,
}

const TYPE_A: u16 = RecordType::A as u16;
const TYPE_NS: u16 = RecordType::Ns as u16;
const TYPE_CNAME: u16 = RecordType::Cname as u16;
const TYPE_SOA: u16 = RecordType::Soa as u16;
const TYPE_WKS: u16 = RecordType::Wks as u16;
const TYPE_PTR: u16 = RecordType::Ptr as u16;
const TYPE_MINFO: u16 = RecordType::Minfo as u16;
const TYPE_HINFO: u16 = RecordType::Hinfo as u16;
const TYPE_MX: u16 = RecordType::Mx as u16;
const TYPE_TXT: u16 = RecordType::Txt as u16;

#[derive(Debug, Clone, PartialEq)]
pub enum RecordData {
    A(Ipv4Addr),
    Ns(String),
    Cname(String),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Wks {
        adress: Ipv4Addr,
        protocol: u8,
        bitmap: Vec<u8>,
    },
    Hinfo {
        cpu: String,
        os: String,
    },
    Minfo {
        rmailbx: String,
        emailbx: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Unknown(u16, Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_to_bytes() {
        let record_a = RecordType::A;
        let bytes = (record_a as u16).to_be_bytes();
        assert_eq!(bytes, [0x00, 0x01]); // A = 1 in big-endian

        let record_txt = RecordType::Txt;
        let bytes = (record_txt as u16).to_be_bytes();
        assert_eq!(bytes, [0x00, 0x10]); // TXT = 16 in big-endian
    }

    #[test]
    fn test_dns_header_flags_encode_decode() {
        let flags = DnsHeaderFlags {
            qr: true,
            opcode: OpCodeOptions::_ServerStatusRequest as u8,
            aa: true,
            tc: false,
            rd: true,
            ra: false,
            z: 3,
            rcode: 5,
        };

        let decoded = DnsHeaderFlags::_from_u16(flags.to_u16());

        assert_eq!(decoded.qr, flags.qr);
        assert_eq!(decoded.opcode, flags.opcode);
        assert_eq!(decoded.aa, flags.aa);
        assert_eq!(decoded.tc, flags.tc);
        assert_eq!(decoded.rd, flags.rd);
        assert_eq!(decoded.ra, flags.ra);
        assert_eq!(decoded.z, flags.z);
        assert_eq!(decoded.rcode, flags.rcode);
    }

    #[test]
    fn test_dns_message_new_query() {
        let (msg, _id) =
            DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);

        assert_eq!(msg.header.qd_count, 1);
        assert_eq!(msg.header.an_count, 0);
        assert_eq!(msg.header.ns_count, 0);
        assert_eq!(msg.header.ar_count, 0);

        assert_eq!(msg.question.name, "example.com");
        assert_eq!(msg.question.record_type, RecordType::A as u16);
        assert_eq!(msg.question.class, 1);

        assert!(msg.answer.is_empty());
        assert!(msg.authority.is_empty());
        assert!(msg.additional.is_empty());
    }

    #[test]
    fn test_dns_message_encode_query() {
        let (msg, _id) =
            DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);
        let bytes = msg.encode_query();

        // At least 12 bytes from header + question
        assert!(bytes.len() > 12);

        // Verify ID on header
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(id, msg.header.id);

        // Verify flags on header
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(flags, msg.header.flags);

        // Verify qd_count
        let qd_count = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(qd_count, msg.header.qd_count);

        assert!(!bytes[12..].is_empty());
    }

    #[test]
    fn test_dns_message_new_query_different_record_types() {
        let record_types = [
            RecordType::A,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Cname,
            RecordType::Ns,
        ];

        for &rec in record_types.iter() {
            let (msg, _id) =
                DnsMessage::new_query("example.com", rec, OpCodeOptions::StandardQuery);

            assert_eq!(msg.question.name, "example.com");
            assert_eq!(msg.question.record_type, rec as u16);
            assert_eq!(msg.question.class, 1);

            assert_eq!(msg.header.qd_count, 1);
            assert_eq!(msg.header.an_count, 0);
            assert_eq!(msg.header.ns_count, 0);
            assert_eq!(msg.header.ar_count, 0);

            assert!(msg.answer.is_empty());
            assert!(msg.authority.is_empty());
            assert!(msg.additional.is_empty());

            let bytes = msg.encode_query();
            assert!(bytes.len() > 12);
            let encoded_type = u16::from_be_bytes([bytes[bytes.len() - 4], bytes[bytes.len() - 3]]);
            assert_eq!(encoded_type, rec as u16);
        }
    }
}
