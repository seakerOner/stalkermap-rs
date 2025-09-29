//! # Stalkermap DNS Resolver (Work in progress)
//!
//! This module defines the basic data structures for representing a DNS message.
//! It includes the header and the main sections (question, answer, authority, additional).
//! These structs can be used to build, parse, and inspect DNS messages

/// Represents a full DNS message, including header and all sections.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct DnsMessage {
    pub(crate) header: HeaderSection,
    // The question for the name server
    pub(crate) question: QuestionSection,
    // RRs answering the question
    pub(crate) answer: AnswerSection,
    // RRs pointing toward an authority
    pub(crate) authority: AuthoritySection,
    // RRs holding additional information
    pub(crate) additional: AdditionalSection,
}

/// Represents the header section of a DNS message.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct HeaderSection {
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

/// Represents the 16-bit DNS flags field (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct DnsHeaderFlags {
    pub(crate) qr: bool,
    pub(crate) opcode: u8,
    pub(crate) aa: bool,
    pub(crate) tc: bool,
    pub(crate) rd: bool,
    pub(crate) ra: bool,
    pub(crate) z: u8,
    pub(crate) rcode: u8,
}

impl DnsHeaderFlags {
    /// Encode the flags into a 16-bit integer.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub(crate) fn from_u16(value: u16) -> Self {
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

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct QuestionSection {
    /// The domain name being queried.
    pub(crate) name: String,
    /// The type of DNS record being requested (e.g., A, AAAA, MX).
    pub(crate) record_type: u16,
    /// The class of the DNS record (usually IN for Internet, or CH for Chaos).
    pub(crate) class: u16,
}

/// Represents a single answer record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct AnswerSection {
    /// The domain name that owns this record.
    pub(crate) owner_name: String,
    /// The type of DNS record (e.g., A, AAAA, CNAME).
    pub(crate) record_type: u16,
    /// The class of the DNS record (usually IN).
    pub(crate) class: u16,
    /// Time-to-live of the record in seconds.
    pub(crate) ttl: i32,
    /// Length of the RDATA field.
    pub(crate) rd_length: u16,
    /// The actual resource data (e.g., IP address for A record).
    pub(crate) r_data: String,
}

/// Represents a single authority record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct AuthoritySection {
    /// The domain name that owns this record.
    pub(crate) owner_name: String,
    /// The type of DNS record.
    pub(crate) record_type: u16,
    /// The class of the DNS record.
    pub(crate) class: u16,
    /// Time-to-live of the record in seconds.
    pub(crate) ttl: u32,
    /// Length of the RDATA field.
    pub(crate) rd_length: u16,
    /// The actual resource data (e.g., authoritative name server).
    pub(crate) r_data: String,
}

/// Represents a single additional record in a DNS message.
/// All RRs (resource records) have the same top level format shown.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct AdditionalSection {
    /// The domain name that owns this record.
    pub(crate) owner_name: String,
    /// The type of DNS record.
    pub(crate) record_type: u16,
    /// The class of the DNS record.
    pub(crate) class: u16,
    /// Time-to-live of the record in seconds.
    pub(crate) ttl: u32,
    /// Length of the RDATA field.
    pub(crate) rd_length: u16,
    /// The actual resource data (e.g., additional IP information).
    pub(crate) r_data: String,
}

/// TYPE fields are used in resource records.  Note that these types are a subset of QTYPEs.
///
/// Make sure for when using it for the Dns message you encode it like shown below:
///
/// # Example
/// ```rust,no_run
/// //use stalkermap::dns::resolver::RecordType;
///
/// //let record_type = RecordType::A.to_bytes();
/// ```
#[allow(dead_code)]
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
    //Wks = 11,
    // A domain name pointer
    Ptr = 12,
    // Host information
    //Hinfo = 13,
    // Mailbox or mail list information
    //Minfo = 14,
    // Mail exchange
    //Mx = 15,
    // Text strings
    Txt = 16,
    //Aaaa = 28,
    //Srv = 33,
    //Naptr = 35,
    //Caa = 257,
}

#[allow(clippy::wrong_self_convention)]
impl RecordType {
    #[allow(dead_code)]
    pub(crate) fn to_bytes(self) -> [u8; 2] {
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
            opcode: 2,
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
}
