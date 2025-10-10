//! DNS Message Compressor (Agnostic Usage)
//!
//! This struct provides a low-level, RFC1035-compliant mechanism for compressing
//! domain names within DNS messages. It is designed to be agnostic of any specific
//! DNS message struct, allowing users to integrate it with their own message construction logic
//! or with the `DnsMessage` struct provided by this library.
//!
//! # Overview
//!
//! In DNS, domain names can be repeated multiple times in a message (e.g., in
//! questions, answers, authority, and additional sections). To reduce message
//! size, RFC1035 §4.1.4 defines a compression scheme:
//!
//! - A domain name, or any suffix of a domain name, can be replaced with a
//!   2-byte pointer to a previous occurrence of the same name in the message.
//! - The pointer is encoded as a 16-bit value where:
//!   - The top two bits are `11`
//!
//!   - The lower 14 bits represent the offset from the start of the message
//! - This compressor builds the message incrementally:
//! 1. The `message` buffer is updated with the compressed domain name bytes.
//! 2. The `pointer_map` keeps track of each suffix and its offset in the buffer,
//!    allowing reuse of previous labels with pointers.
//! 3. Each label is validated against DNS limits (63 bytes per label, 255 bytes
//!    per full domain name). Errors are returned if limits are exceeded.
//!
//! # Usage
//!
//! Users can either build a DNS message manually using their own structures
//! or use the `DnsMessage` struct provided by this library. Example with a raw buffer:
//!
//! ```rust,ignore
//! use std::collections::HashMap;
//! use stalkermap::dns::compressor::agnostic::MessageCompressor;
//!
//! let mut message = Vec::new();
//! let mut pointer_map = HashMap::new();
//!
//! // Compress a domain name
//! MessageCompressor::compress("www.example.com", &mut message, &mut pointer_map).unwrap();
//!
//! // Reusing the same domain (or suffix) inserts a pointer instead of repeating bytes
//! MessageCompressor::compress("mail.example.com", &mut message, &mut pointer_map).unwrap();
//! ```
//!
//! # Notes
//!
//! - This compressor does **not** manage full DNS message sections, headers, or
//!   resource records—it only handles domain name compression.
//! - Users are responsible for passing the mutable `message` buffer and the
//!   mutable `pointer_map` for incremental building of DNS messages.
//! - The compressor returns `CompressorErrors` for:
//!   - Labels longer than 63 bytes (`LabelTooLong`)
//!   - Domain names longer than 255 bytes (`InvalidName`)
//!
//! # References
//! - RFC1035 §4.1.4 (Domain Name Representation and Compression)
//! - <https://datatracker.ietf.org/doc/html/rfc1035>
use std::{collections::HashMap, error::Error, fmt::Display};

#[derive(PartialEq, Eq, Hash)]
pub struct MessageCompressor {}

impl MessageCompressor {
    /// Reference to RFC1035, page 30 (4.1.4)
    ///
    /// In order to reduce the size of messages, the domain system utilizes a
    /// compression scheme which eliminates the repetition of domain names in a
    /// message.  In this scheme, an entire domain name or a list of labels at
    /// the end of a domain name is replaced with a pointer to a prior occurance
    /// of the same name.
    ///
    /// The pointer takes the form of a two octet sequence:
    ///
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   | 1  1|                OFFSET                   |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// The first two bits are ones.  This allows a pointer to be distinguished
    /// from a label, since the label must begin with two zero bits because
    /// labels are restricted to 63 octets or less.  (The 10 and 01 combinations
    /// are reserved for future use.)  The OFFSET field specifies an offset from
    /// the start of the message (i.e., the first octet of the ID field in the
    /// domain header).  A zero offset specifies the first byte of the ID field,
    /// etc.
    pub fn compress(
        name: &str,
        message: &mut Vec<u8>,
        pointer_map: &mut HashMap<String, usize>,
    ) -> Result<(), CompressorErrors> {
        let labels: Vec<&str> = name.split('.').collect();
        // Position is the current offset inside the buffer.
        // pointer_map -> (suffix, position)
        let mut position = message.len();

        // If name is bigger than 255 bytes
        if name.len() >= 0xFF {
            return Err(CompressorErrors::InvalidName(name.to_string()));
        }

        if name == "." || name.is_empty() {
            message.push(0);
            return Ok(());
        }

        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");

            if let Some(&offset) = pointer_map.get(&suffix) {
                // make sure offset fits in 14 bits
                // 0x3FFF -> mask to represent lowest 14 bits of a u16 value
                if offset <= 0x3FFF {
                    // Pointer: top 2 bits is the pointer (number 11), the rest is the offset -> max 14 bits
                    // creating the u16 pointer manually
                    let pointer = 0b1100_0000_0000_0000u16 | (offset as u16);
                    message.extend_from_slice(&pointer.to_be_bytes());
                    return Ok(());
                } else {
                    //offset to large to encode as a pointer; writing labels normally
                    let label = labels[i];
                    let len = label.len();

                    if len > 63 {
                        return Err(CompressorErrors::LabelTooLong(label.to_string()));
                    }
                    message.push(label.len() as u8);
                    message.extend_from_slice(label.as_bytes());

                    position += 1 + label.len();
                }
            } else {
                pointer_map.insert(suffix.clone(), position);

                let label = labels[i];
                let len = label.len();

                if len > 63 {
                    return Err(CompressorErrors::LabelTooLong(label.to_string()));
                }
                message.push(label.len() as u8);
                message.extend_from_slice(label.as_bytes());

                position += 1 + label.len();
            }
        }

        message.push(0);
        Ok(())
    }
}

#[derive(Debug)]
pub enum CompressorErrors {
    LabelTooLong(String),
    InvalidName(String),
}

impl Display for CompressorErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressorErrors::LabelTooLong(s) => write!(f, "Label too long (>63): {}", s),
            CompressorErrors::InvalidName(s) => write!(f, "Name is to long (>255): {}", s),
        }
    }
}

impl Error for CompressorErrors {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressor_basic_compression() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        let name = "example.com";
        MessageCompressor::compress(name, &mut message, &mut pointer_map).unwrap();

        // "example" = 7, "com" = 3, null terminator
        let expected = [
            7u8, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3u8, b'c', b'o', b'm', 0u8,
        ];
        assert_eq!(message, expected);
    }

    #[test]
    fn test_compressor_compression_with_pointer() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        MessageCompressor::compress("example.com", &mut message, &mut pointer_map).unwrap();
        let first_len = message.len();

        // Reusing the same name should produce a pointer
        MessageCompressor::compress("example.com", &mut message, &mut pointer_map).unwrap();

        // The pointer is 2 bytes with top bits 11
        let pointer_bytes = &message[first_len..];
        assert_eq!(pointer_bytes.len(), 2);
        assert_eq!(pointer_bytes[0] >> 6, 0b11); // top 2 bits are 11
    }

    #[test]
    fn test_compressor_label_too_long() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        let long_label = "a".repeat(64); // >63 bytes
        let name = format!("{}.com", long_label);
        let result = MessageCompressor::compress(&name, &mut message, &mut pointer_map);
        assert!(matches!(result, Err(CompressorErrors::LabelTooLong(_))));
    }

    #[test]
    fn test_compressor_name_too_long() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        // 256 bytes name
        let long_name = format!("{}.", "a".repeat(256));
        let result = MessageCompressor::compress(&long_name, &mut message, &mut pointer_map);
        assert!(matches!(result, Err(CompressorErrors::InvalidName(_))));
    }

    #[test]
    fn test_compressor_root_label() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        MessageCompressor::compress(".", &mut message, &mut pointer_map).unwrap();
        assert_eq!(message, vec![0u8]);

        message.clear();
        MessageCompressor::compress("", &mut message, &mut pointer_map).unwrap();
        assert_eq!(message, vec![0u8]);
    }

    #[test]
    fn test_compressor_multiple_labels_and_suffixes() {
        let mut message = Vec::new();
        let mut pointer_map = HashMap::new();

        MessageCompressor::compress("www.example.com", &mut message, &mut pointer_map).unwrap();
        let len_after_first = message.len();

        // Reuse "example.com", should produce pointer only for suffix
        MessageCompressor::compress("mail.example.com", &mut message, &mut pointer_map).unwrap();

        assert!(message.len() > len_after_first);
        // Check that suffix "example.com" was replaced by pointer
        let pointer_pos = len_after_first + 1 + 4; // mail has 4 bytes
        let pointer_bytes = &message[pointer_pos..pointer_pos + 2];
        assert_eq!(pointer_bytes[0] >> 6, 0b11); // top 2 bits is 11
    }
}
