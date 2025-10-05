//! # Stalkermap DNS Resolver
//!
//! A lightweight, blocking DNS resolver built in pure Rust, fully aligned with [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).
//!
//! This module provides a simple interface for performing DNS lookups over UDP without external dependencies.
//! The focus is on **synchronous resolution** via the `std` feature, allowing you to easily retrieve common DNS record types such as A, CNAME, MX, and TXT.
//!
//! ## Features
//!
//! - **Blocking UDP resolver** (enabled with `std`).
//! - Queries support multiple record types (`A`, `CNAME`, `SOA`, `MX`, `TXT`, and others).
//! - Designed for simplicity, correctness, and small binary size.
//!
//! ### Available Features
//!
//! | Feature       | Description                                                                 |
//! |----------------|------------------------------------------------------------------------------|
//! | `std`          | Enables the blocking UDP resolver (recommended).                            |
//! | `tokio-dep`    | Planned asynchronous version (not yet implemented).                         |
//! | `agnostic`     | Provides only message encoding/decoding (no network transport).              |
//!
//! > ⚠️ **Note:** `agnostic` cannot be enabled together with `std` or `tokio-dep`.
//!
//! ## Quick Start
//!
//! Example of resolving an IPv4 address (A record):
//!
//! ```rust,ignore
//! use stalkermap::dns::resolver::resolve_ipv4;
//!
//! match resolve_ipv4("example.com") {
//!    Ok(response) => {
//!        for answer in response.answer {
//!            println!("Answer: {:?}", answer);
//!       }
//!    }
//!    Err(e) => eprintln!("DNS resolution failed: {e}"),
//! }
//! ```
//!
//! You can also resolve other record types:
//!
//! ```rust,ignore
//! use stalkermap::dns::resolver::{resolve_cname, resolve_mx, resolve_txt};
//!
//! let _ = resolve_cname("www.example.com");
//! let _ = resolve_mx("example.com");
//! let _ = resolve_txt("example.com");
//! ```
//!
//! ##  Technical Notes
//!
//! Internally, all DNS messages are encoded and decoded using types that implement RFC 1035 fields and bit-level semantics
//! (headers, questions, answers, and name compression).
//!
//! These lower-level structures are **not required for regular use**, but are exposed under the `agnostic` feature for advanced integrations.
//!
//! The resolver automatically uses a set of system-specific or public DNS servers (see `transporter::get_servers()`).
//!
//! ##  Error Handling
//!
//! The resolver returns structured errors with clear descriptions:
//!
//! - `ResolverErrors` — high-level errors from the public API.
//! - `UdpErrors` — network or socket-related failures (timeouts, invalid response IDs, etc.).
//! - `DecodeQueryErrors` — internal decoding issues (only visible through `UdpErrors`).
//!
//! Each error implements `Display` and `Error`, making them easy to use with `?` or `anyhow`.
//!
//! ##  Example Output
//!
//! ```text
//! DnsMessage {
//!     header: HeaderSection { id: 4201, flags: 33152, qd_count: 1, an_count: 1, .. },
//!     question: QuestionSection { name: "example.com", record_type: 1, class: 1 },
//!     answer: [ AnswerSection { owner_name: "example.com", record_type: 1, r_data: [93, 184, 216, 34] } ],
//!     authority: [],
//!     additional: [],
//! }
//! ```
//!
//! ## Future Development
//!
//! - `tokio-dep`: Asynchronous resolver for non-blocking DNS lookups.  
//! - Support for additional record types (AAAA, SRV, NAPTR).  
//! - Optional caching and EDNS(0) extensions.
//!
#[cfg(all(feature = "agnostic", any(feature = "std", feature = "tokio-dep")))]
compile_error!("Features `agnostic` and (`std`/`tokio`) cannot be enabled at the same time");

cfg_if::cfg_if! {
    if #[cfg(any(feature = "agnostic"))] {
        pub mod agnostic;
        pub use self::agnostic::{
            AdditionalSection, AnswerSection, AuthoritySection, DnsHeaderFlags, DnsMessage, HeaderSection,
            OpCodeOptions, QuestionSection, RecordType, generate_id
        };
    } else if #[cfg(any(feature = "std", feature = "tokio-dep"))] {
        mod standard;
        pub(crate) use self::standard::{
            OpCodeOptions, RecordType
        };
        pub use self::standard::{
            DnsMessage, DecodeQueryErrors
        };
    } else if #[cfg(doc)] {
        // For documentation builds only — provide dummy types
        #[allow(dead_code)]
        #[derive(Debug)]
        pub enum DecodeQueryErrors {
            /// Placeholder type for documentation mode.
            NotApplicable,
        }

        #[allow(dead_code)]
        #[derive(Debug)]
        pub struct DnsMessage;

        #[allow(dead_code)]
        #[derive(Debug)]
        pub enum RecordType {}

        #[allow(dead_code)]
        #[derive(Debug)]
        pub enum OpCodeOptions {}
    }
}

pub mod transporter;

cfg_if::cfg_if! {
    if #[cfg(any( feature = "std", feature = "tokio-dep", all(doc, not(feature = "agnostic"))))]  {
        use std::{error::Error, fmt::Display, time::Duration};
        use std::net::{UdpSocket};
        use transporter::get_servers;



        /// Resolves an IPv4 (`A`) record for the given domain name using a blocking UDP query.
        ///
        /// # Example
        /// ```rust,ignore
        /// let response = resolve_ipv4("example.com")?;
        /// for answer in response.answer {
        ///     println!("IPv4: {:?}", answer);
        /// }
        /// ```
        ///
        /// # Errors
        /// Returns [`ResolverErrors`] if the query could not be sent or decoded.
        pub fn resolve_ipv4(name: &str) -> Result<DnsMessage, ResolverErrors>{
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::A, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a canonical name (`CNAME`) record for the given domain name.
        ///
        /// This record maps an alias name to its true, canonical domain name.
        pub fn resolve_cname(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Cname, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Start of Authority (`SOA`) record for the given domain name.
        ///
        /// The SOA record defines the authoritative DNS server and zone parameters.
        pub fn resolve_soa(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Soa, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }


            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Well-Known Services (`WKS`) record for the given domain name.
        ///
        /// The WKS record describes network services associated with an address.
        pub fn resolve_wks(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Wks, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        pub fn resolve_ptr(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Ptr, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }


            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Host Information (`HINFO`) record for the given domain name.
        pub fn resolve_hinfo(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Hinfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Mail Information (`MINFO`) record for the given domain name.
        pub fn resolve_minfo(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Minfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Mail Exchange (`MX`) record for the given domain name.
        ///
        /// MX records define the mail servers responsible for handling email for the domain.
        pub fn resolve_mx(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Mx, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Text (`TXT`) record for the given domain name.
        ///
        /// Commonly used for SPF, DKIM, and general verification data.
        pub fn resolve_txt(name: &str) -> Result<DnsMessage, ResolverErrors> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Txt, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_blocking(bytes, id) {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrors::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        fn send_query_blocking(query: Vec<u8>, id: u16) -> Result<DnsMessage, UdpErrors> {
            let servers = get_servers();
            let svr_len = servers.len();
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => return Err(UdpErrors::SocketIo(e))
            };
            match socket.set_read_timeout(Some(Duration::from_secs(3))) {
                Ok(_) => {},
                Err(e) => return Err(UdpErrors::SocketIo(e))
            }

            let mut sv_cont = 0;
            for server in servers.iter() {
                match socket.send_to(&query, server) {
                    Ok(_) => break,
                    Err(_) => {
                        sv_cont += 1;
                        if sv_cont == svr_len { return Err(UdpErrors::CouldNotSendMessage)}
                        continue
                    }
                }
            }

            let mut buf = [0u8; 512];
            let (len, _src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => return Err(UdpErrors::NoResponse)
            };


            let response = &buf[..len];
            match internal::check_response_id([response[0], response[1]], id) {
                true => {},
                false => return Err(UdpErrors::IdResponseInvalid(id))
            }
            let dns_msg = match DnsMessage::decode_query(response) {
                Ok(v) => v,
                Err(e) => return Err(UdpErrors::DecodeQueryErrors(e))
            };

            Ok(dns_msg)
        }

        /// Represents errors that may occur when sending or receiving DNS queries over UDP.
        #[derive(Debug)]
        pub enum UdpErrors{
            SocketIo(std::io::Error),
            IdResponseInvalid(u16),
            CouldNotSendMessage,
            NoResponse,
            DecodeQueryErrors(DecodeQueryErrors)
        }

        impl Display for UdpErrors {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    UdpErrors::SocketIo(e) => write!(f, "{}", e),
                    UdpErrors::IdResponseInvalid(id) => write!(f,
                        "The DNS query's response ID didn't match with the DNS question sent.\nId: {}", id),
                    UdpErrors::CouldNotSendMessage => write!(f, "Could not send the DNS message over UDP with any DNS name server from the server list"),
                    UdpErrors::NoResponse => write!(f, "Could not get a DNS response from the DNS name server list."),
                    UdpErrors::DecodeQueryErrors(e) => write!(f, "{}", e)
                }
            }
        }

        /// Represents high-level resolver errors exposed to users.
        #[derive(Debug)]
        pub enum ResolverErrors {
            SendingUdpQuery(UdpErrors)
        }

        impl Display for ResolverErrors{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    ResolverErrors::SendingUdpQuery(e) => write!(f, "{}", e)
                }
            }
        }

        impl Error for ResolverErrors {}

        impl From<std::io::Error> for UdpErrors {
            fn from(value: std::io::Error) -> Self {
                UdpErrors::SocketIo(value)
            }
        }

        impl Error for UdpErrors {
        }

        mod internal {
            pub(crate) fn check_response_id(id_in_bytes: [u8; 2], id: u16 ) -> bool{
                id == u16::from_be_bytes(id_in_bytes)
            }
        }
    }
}
