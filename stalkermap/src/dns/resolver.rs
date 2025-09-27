//! # Stalkermap DNS Resolver
//!
//! This module defines the basic data structures for representing a DNS message.
//! It includes the header and the main sections (question, answer, authority, additional).
//! These structs can be used to build, parse, and inspect DNS messages

/// Represents a full DNS message, including header and all sections.
#[derive(Debug)]
struct DnsMessage {
    header: HeaderSection,
    question: QuestionsSection,
    answer: AnswerSection,
    authority: AuthoritySection,
    additional: AdditionalSection,
}

/// Represents the header section of a DNS message.
#[derive(Debug)]
struct HeaderSection {
    /// Identifier to match requests and responses.
    id: u16,
    /// Flags and control bits for the DNS message.
    flags: u16,
    /// Number of entries in the question section.
    qd_count: u16,
    /// Number of resource records in the answer section.
    an_count: u16,
    /// Number of name server records in the authority section.
    ns_count: u16,
    /// Number of resource records in the additional section.
    ar_count: u16,
}

#[derive(Debug)]
struct QuestionsSection {
    /// The domain name being queried.
    name: String,
    /// The type of DNS record being requested (e.g., A, AAAA, MX).
    record_type: u16,
    /// The class of the DNS record (usually IN for Internet, or CH for Chaos).
    class: u16,
}

/// Represents a single answer record in a DNS message.
#[derive(Debug)]
struct AnswerSection {
    /// The domain name that owns this record.
    owner: String,
    /// The type of DNS record (e.g., A, AAAA, CNAME).
    record_type: u16,
    /// The class of the DNS record (usually IN).
    class: u16,
    /// Time-to-live of the record in seconds.
    ttl: u32,
    /// Length of the RDATA field.
    rd_length: u16,
    /// The actual resource data (e.g., IP address for A record).
    r_data: String,
}

/// Represents a single authority record in a DNS message.
#[derive(Debug)]
struct AuthoritySection {
    /// The domain name that owns this record.
    owner: String,
    /// The type of DNS record.
    record_type: u16,
    /// The class of the DNS record.
    class: u16,
    /// Time-to-live of the record in seconds.
    ttl: u32,
    /// Length of the RDATA field.
    rd_length: u16,
    /// The actual resource data (e.g., authoritative name server).
    r_data: String,
}

/// Represents a single additional record in a DNS message.
#[derive(Debug)]
struct AdditionalSection {
    /// The domain name that owns this record.
    owner: String,
    /// The type of DNS record.
    record_type: u16,
    /// The class of the DNS record.
    class: u16,
    /// Time-to-live of the record in seconds.
    ttl: u32,
    /// Length of the RDATA field.
    rd_length: u16,
    /// The actual resource data (e.g., additional IP information).
    r_data: String,
}

enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Hinfo = 13,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Naptr = 35,
    Caa = 257,
}
