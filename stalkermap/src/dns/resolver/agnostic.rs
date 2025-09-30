//! # Stalkermap DNS Resolver – Agnostic Mode
//!
//! This module provides the low-level building blocks for working with DNS messages
//! in an **agnostic** way. Unlike the standard resolver, this mode does not perform
//! any network I/O or send queries/responses by itself. Instead, it focuses on
//! constructing and encoding/decoding DNS messages according to [RFC 1035].
//!
//! ## When to use agnostic mode
//! Use this mode if you need fine-grained control over DNS messages, for example:
//! - Implementing your own scanner, fuzzer, or resolver logic.
//! - Generating custom DNS queries to send over raw sockets.
//! - Parsing and inspecting DNS responses manually.
//!
//! ## What this mode provides
//! - A [`DnsMessage`] struct to hold the full DNS message (header, question, answer, authority, additional).
//! - [`HeaderSection`] with support for encoding/decoding [`DnsHeaderFlags`].
//! - [`QuestionSection`] and resource record structs ([`AnswerSection`], [`AuthoritySection`], [`AdditionalSection`]).
//! - An [`OpCodeOptions`] enum for the DNS opcodes (Standard, Inverse, ServerStatus).
//! - A [`RecordType`] enum with common record types (A, MX, TXT, etc.).
//! - Integration with [`MessageCompressor`] to apply RFC 1035-compliant name compression.
//!
//! ## Example
//! ```rust,no_run
//! use stalkermap::dns::resolver::agnostic::{DnsMessage, RecordType, OpCodeOptions};
//!
//! // Build a query for example.com A record
//! let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);
//!
//! // Encode into raw bytes, ready to send via UDP/TCP
//! let bytes = msg.encode_query();
//!
//! assert!(bytes.len() > 12); // includes header + question
//! ```
//!
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035

use crate::dns::compressor::MessageCompressor;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::collections::HashMap;

/// Generates a random 16-bit ID for a DNS query.
pub fn generate_id() -> u16 {
    let mut thread_rng = rand::rng();
    let mut rng = SmallRng::from_rng(&mut thread_rng);

    rng.random::<u16>()
}

/// Represents a full DNS message, including the header and all four sections.
///
/// A DNS message is composed of:
/// - [`HeaderSection`] – metadata, flags, and counters.
/// - [`QuestionSection`] – the query being asked.
/// - [`AnswerSection`] – responses containing resource records.
/// - [`AuthoritySection`] – information about authoritative name servers.
/// - [`AdditionalSection`] – extra information to help resolve queries.
///
/// Usually constructed via [`DnsMessage::new_query`].
///
/// # Example
/// ```rust,no_run
/// use stalkermap::dns::resolver::agnostic::{DnsMessage, RecordType, OpCodeOptions};
///
/// let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);
/// let bytes = msg.encode_query();
/// assert!(bytes.len() > 12);
/// ```
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
    /// Creates a new standard query message.
    ///
    /// # Arguments
    /// * `target` - The domain name to query.
    /// * `record_type` - Type of record (A, MX, TXT, etc.).
    /// * `query_type` - DNS operation code (Standard, Inverse, or ServerStatus).
    pub fn new_query(
        target: &str,
        record_type: RecordType,
        query_type: OpCodeOptions,
    ) -> DnsMessage {
        DnsMessage {
            header: HeaderSection {
                id: generate_id(), //random u16 number
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
        }
    }

    /// Encodes the DNS query into bytes for sending over the network.
    ///
    /// This uses RFC1035-compliant compression on domain names via `MessageCompressor`.
    pub fn encode_query(&self) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();
        let mut pointer_map: HashMap<String, usize> = HashMap::new();

        message.extend_from_slice(&self.header.to_bytes());

        MessageCompressor::compress(&self.question.name, &mut message, &mut pointer_map).unwrap();
        message.extend_from_slice(&self.question.record_type.to_be_bytes());
        message.extend_from_slice(&self.question.class.to_be_bytes());
        message
    }
}

/// Represents the header section of a DNS message (RFC 1035 §4.1.1).
///
/// Contains:
/// - A 16-bit identifier (`id`) to match requests and responses.
/// - Flags and control bits (`flags`), usually built with [`DnsHeaderFlags`].
/// - Counts for the number of entries in each section.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeaderSection {
    /// Identifier to match requests and responses.
    pub id: u16,
    /// Flags and control bits for the DNS message.
    /// Use [`DnsHeaderFlags`]
    pub flags: u16,
    /// Number of entries in the question section.
    pub qd_count: u16,
    /// Number of resource records in the answer section.
    pub an_count: u16,
    /// Number of name server records in the authority section.
    pub ns_count: u16,
    /// Number of resource records in the additional section.
    pub ar_count: u16,
}

impl HeaderSection {
    /// Converts the header into a 12-byte array suitable for network transmission.
    pub fn to_bytes(&self) -> [u8; 12] {
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
///
/// Provides easy encode/decode between structured flags and the raw `u16`.
///
/// - `qr`: Query/Response (false = query, true = response)
/// - `opcode`: DNS operation code, see [`OpCodeOptions`]
/// - `aa`: Authoritative Answer
/// - `tc`: Truncated message
/// - `rd`: Recursion Desired
/// - `ra`: Recursion Available
/// - `z`: Reserved (must be 0 in queries)
/// - `rcode`: Response code (e.g., NXDOMAIN)
///
/// # Example
/// ```rust,no_run
/// use stalkermap::dns::resolver::agnostic::{DnsHeaderFlags, OpCodeOptions};
///
/// let flags = DnsHeaderFlags {
///     qr: false,
///     opcode: OpCodeOptions::StandardQuery as u8,
///     aa: false,
///     tc: false,
///     rd: true,
///     ra: false,
///     z: 0,
///     rcode: 0,
/// };
///
/// let encoded = flags.to_u16();
/// let decoded = DnsHeaderFlags::from_u16(encoded);
///
/// assert_eq!(decoded.qr, false);
/// assert_eq!(decoded.opcode, OpCodeOptions::StandardQuery as u8);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DnsHeaderFlags {
    /// Query/Response flag
    pub qr: bool,
    /// Operation code
    /// Use `OpCodeOptions`
    pub opcode: u8,
    /// Authoritative Answer
    pub aa: bool,
    /// Truncation flag
    pub tc: bool,
    /// Recursion Desired
    pub rd: bool,
    /// Recursion Available
    pub ra: bool,
    /// Reserved bits (RFC 1035)
    pub z: u8,
    /// Response code
    pub rcode: u8,
}

/// Operation codes available for DNS queries (RFC 1035 §4.1.1).
///
/// - `StandardQuery` – typical A, MX, TXT lookups.
/// - `InverseQuery` – legacy, rarely used.
/// - `ServerStatusRequest` – request server status (obsolete).
// 3-15 reserved for future use
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCodeOptions {
    StandardQuery = 0,
    InverseQuery = 1,
    ServerStatusRequest = 2,
}

impl DnsHeaderFlags {
    /// Encode the flags into a 16-bit integer.
    pub fn to_u16(self) -> u16 {
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
    pub fn from_u16(value: u16) -> Self {
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

/// Represents the question section of a DNS message.
///
/// Contains:
/// - The domain name being queried (`name`)
/// - The type of record requested (`record_type`) — see [`RecordType`]
/// - The class of the DNS record (usually `IN` = Internet)
#[derive(Debug, Clone, PartialEq)]
pub struct QuestionSection {
    /// The domain name being queried.
    pub name: String,
    /// The type of DNS record being requested (e.g., A, AAAA, MX).
    pub record_type: u16,
    /// The class of the DNS record (usually IN for Internet, or CH for Chaos).
    pub class: u16,
}

/// Represents a single resource record (RR) in the DNS message.
///
/// All RRs share the same format:
/// - `owner_name` – domain name that owns the record
/// - `record_type` – type (A, MX, etc.)
/// - `class` – class (usually IN)
/// - `ttl` – time-to-live
/// - `rd_length` – length of `r_data`
/// - `r_data` – the actual data (e.g., IP address, hostname)
///
/// Used in:
/// - [`AnswerSection`] – responses to the query
/// - [`AuthoritySection`] – authoritative name server info
/// - [`AdditionalSection`] – extra resolving hints
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
    pub r_data: String,
}

/// Represents a single resource record (RR) in the DNS message.
///
/// All RRs share the same format:
/// - `owner_name` – domain name that owns the record
/// - `record_type` – type (A, MX, etc.)
/// - `class` – class (usually IN)
/// - `ttl` – time-to-live
/// - `rd_length` – length of `r_data`
/// - `r_data` – the actual data (e.g., IP address, hostname)
///
/// Used in:
/// - [`AnswerSection`] – responses to the query
/// - [`AuthoritySection`] – authoritative name server info
/// - [`AdditionalSection`] – extra resolving hints
#[derive(Debug, Clone, PartialEq)]
pub struct AuthoritySection {
    /// The domain name that owns this record.
    pub owner_name: String,
    /// The type of DNS record.
    pub record_type: u16,
    /// The class of the DNS record.
    pub class: u16,
    /// Time-to-live of the record in seconds.
    pub ttl: u32,
    /// Length of the RDATA field.
    pub rd_length: u16,
    /// The actual resource data (e.g., authoritative name server).
    pub r_data: String,
}

/// Represents a single resource record (RR) in the DNS message.
///
/// All RRs share the same format:
/// - `owner_name` – domain name that owns the record
/// - `record_type` – type (A, MX, etc.)
/// - `class` – class (usually IN)
/// - `ttl` – time-to-live
/// - `rd_length` – length of `r_data`
/// - `r_data` – the actual data (e.g., IP address, hostname)
///
/// Used in:
/// - [`AnswerSection`] – responses to the query
/// - [`AuthoritySection`] – authoritative name server info
/// - [`AdditionalSection`] – extra resolving hints
#[derive(Debug, Clone, PartialEq)]
pub struct AdditionalSection {
    /// The domain name that owns this record.
    pub owner_name: String,
    /// The type of DNS record.
    pub record_type: u16,
    /// The class of the DNS record.
    pub class: u16,
    /// Time-to-live of the record in seconds.
    pub ttl: u32,
    /// Length of the RDATA field.
    pub rd_length: u16,
    /// The actual resource data (e.g., additional IP information).
    pub r_data: String,
}

/// DNS record types (subset of QTYPEs from RFC 1035).
///
/// - `A` – IPv4 address
/// - `Ns` – Authoritative name server
/// - `Cname` – Canonical name
/// - `Soa` – Start of authority
/// - `Mx` – Mail exchange
/// - `Txt` – Text record
///
/// Use [`RecordType::to_bytes`] when encoding queries.
///
/// # Example
/// ```rust,no_run
/// use stalkermap::dns::resolver::agnostic::RecordType;
///
/// let rtype = RecordType::A;
/// let encoded = rtype.to_bytes();
/// assert_eq!(encoded, [0x00, 0x01]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
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

#[allow(clippy::wrong_self_convention)]
impl RecordType {
    /// Encode the record type as a 2-byte big-endian value.
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_to_bytes() {
        let record_a = RecordType::A;
        let bytes = record_a.to_bytes();
        assert_eq!(bytes, [0x00, 0x01]); // A = 1 in big-endian

        let record_txt = RecordType::Txt;
        let bytes = record_txt.to_bytes();
        assert_eq!(bytes, [0x00, 0x10]); // TXT = 16 in big-endian
    }

    #[test]
    fn test_dns_header_flags_encode_decode() {
        let flags = DnsHeaderFlags {
            qr: true,
            opcode: OpCodeOptions::ServerStatusRequest as u8,
            aa: true,
            tc: false,
            rd: true,
            ra: false,
            z: 3,
            rcode: 5,
        };

        let decoded = DnsHeaderFlags::from_u16(flags.to_u16());

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
        let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);

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
        let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);
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
            let msg = DnsMessage::new_query("example.com", rec, OpCodeOptions::StandardQuery);

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
