#![cfg_attr(docsrs, feature(doc_cfg))]
//! # Stalkermap DNS Resolver
//!
//! A lightweight, blocking DNS resolver built in pure Rust, fully compliant with [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).
//!
//! This crate provides both **blocking** and **asynchronous** DNS resolution over UDP.
//!
//! ## Features
//!
//! - **Blocking/Unblocking UDP resolver** (enabled with `std`).
//! - Queries support multiple record types (`A`, `CNAME`, `SOA`, `MX`, `TXT`, and others).
//! - Internally, DNS messages are serialized and parsed using types that model all RFC 1035 structures and bit-level semantics.
//! - Designed for simplicity, correctness, and small binary size.
//!
//! ### Available Features
//!
//! | Feature       | Description                                                                 |
//! |----------------|------------------------------------------------------------------------------|
//! | `std`          | Enables the **blocking** UDP resolver using the standard library.            |
//! | `tokio-dep`    | Enables the **asynchronous** resolver built on [Tokio](https://tokio.rs).    |
//! | `agnostic`     | Provides only message encoding and decoding, with no network I/O.      |
//!
//! > **Note:** `agnostic` cannot be enabled together with `std` or `tokio-dep`.
//!
//! ## Quick Start
//!
//! ### Blocking (standard library)
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
//! ### Asynchronous (Tokio)
//!
//! ```rust,ignore
//! use stalkermap::dns::resolver::{resolve_ipv4_async, resolve_txt_async};
//! use tokio::join;
//!
//! #[tokio::main]
//! async fn main() {
//!     let (a_record, txt_record) = join!(
//!         resolve_ipv4_async("example.com"),
//!         resolve_txt_async("example.com")
//!     );
//!
//!     match a_record {
//!         Ok(ips) => println!("{:#?}", ips),
//!         Err(e) => eprintln!("IPv4 lookup failed: {e}"),
//!     }
//!
//!     match txt_record {
//!         Ok(txts) => println!("{:#?}", txts),
//!         Err(e) => eprintln!("TXT lookup failed: {e}"),
//!     }
//! }
//! ```
//!
//! ## Supported Record Types
//!
//! - `A` — IPv4 address records  
//! - `CNAME` — Canonical name (alias)  
//! - `SOA` — Start of Authority  
//! - `MX` — Mail Exchange  
//! - `TXT` — Text records (SPF, DKIM, etc.)  
//! - `PTR`, `HINFO`, `MINFO`, and `WKS`
//!
//! Each record type has both blocking and asynchronous resolver functions.
//!
//! ```rust,ignore
//! use stalkermap::dns::resolver::{resolve_cname, resolve_mx, resolve_txt};
//!
//! let _ = resolve_cname("www.example.com");
//! let _ = resolve_mx("example.com");
//! let _ = resolve_txt("example.com");
//! ```
//!
//! ## Error Handling
//!
//! Errors are reported through structured types that implement both `Display` and `Error`:
//!
//! - `ResolverErrors` / `ResolverErrorsAsync` — top-level resolver errors from the public API.  
//! - `UdpErrors` / `TokioUdpErrors` — network-related failures such as timeouts or invalid responses.  
//! - `DecodeQueryErrors` — low-level message parsing failures (bubbled up from UDP errors).  
//!
//! This allows ergonomic usage with the `?` operator
//!
//! ##  Technical Notes
//!
//! Internally, all DNS messages are encoded and decoded using types that implement RFC 1035 fields and bit-level semantics
//! (headers, questions, answers, and name compression).
//!
//! These lower-level structures are **not required for regular use**, but are exposed under the `agnostic` feature for advanced integrations.
//!
//! The resolver automatically uses a set of public DNS servers (see `transporter::get_servers()`).
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
//! - Expanded async API (retries, fallback strategies).  
//! - Support for additional record types (AAAA, SRV, NAPTR).  
//! - TCP Fallback and EDNS(0) extensions.
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

        mod tokio_stub {
            pub mod time {
                pub mod error {
                    #[derive(Debug)]
                    pub struct Elapsed;
                }
                pub struct Duration;
                pub async fn timeout<T>(_d: Duration, val: T) -> Result<T, error::Elapsed> {
                    Err(error::Elapsed)
                }
            }
            pub mod net {
                pub struct UdpSocket;
            }
        }
        use tokio_stub as tokio;
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

            match socket.set_write_timeout(Some(Duration::from_secs(3))){
                Ok(_) => {},
                Err(e) => return Err(UdpErrors::SocketIo(e))
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

        // Async functions (tokio-dep)

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

cfg_if::cfg_if! {
    if #[cfg(any(feature = "tokio-dep"))] {
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
        use tokio::time::error::Elapsed;
        use tokio::net::UdpSocket as TokioUdpSocket;
        use tokio::time::{timeout, Duration as TokioDuration };

        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_ipv4_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync>{
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::A, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
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
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_cname_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Cname, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
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
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_soa_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Soa, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
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
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_wks_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Wks, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_ptr_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Ptr, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
            }
            }


            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Host Information (`HINFO`) record for the given domain name.
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_hinfo_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Hinfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        /// Resolves a Mail Information (`MINFO`) record for the given domain name.
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_minfo_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Minfo, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
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
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_mx_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Mx, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
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
        #[cfg_attr(docsrs, doc(cfg(feature = "tokio-dep")))]
        pub async fn resolve_txt_async(name: &str) -> Result<DnsMessage, ResolverErrorsAsync> {
            #[cfg(not(doc))]
            {
            let (msg, id) = DnsMessage::new_query(name, RecordType::Txt, OpCodeOptions::StandardQuery);

            let bytes = msg.encode_query();
            match send_query_async(bytes, id).await {
                Ok(msg) => Ok(msg),
                Err(e) => Err(ResolverErrorsAsync::SendingUdpQuery(e))
            }
            }

            #[cfg(doc)]
            {
                unimplemented!("Stub for documentation only");
            }
        }

        async fn send_query_async(query: Vec<u8>, id: u16) -> Result<DnsMessage, TokioUdpErrors> {
            let servers = get_servers();
            let svr_len = servers.len();
            let socket = match TokioUdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => return Err(TokioUdpErrors::SocketIo(e))
            };

            let timeout_duration = TokioDuration::from_secs(3);

            let mut sv_cont = 0;

            for server in servers.iter() {
                match timeout(timeout_duration, socket.send_to(&query, server)).await {
                   Ok(Ok(_)) => break,
                   Ok(Err(_)) => {
                        sv_cont += 1;
                        if sv_cont == svr_len { return Err(TokioUdpErrors::CouldNotSendMessage)}
                        continue;
                   }
                    Err(e) => {
                        return Err(TokioUdpErrors::Elapsed(e))
                    }

                }
            }

            let mut buf = [0u8; 512];

            let (len, _src) = match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                Ok(Err(_)) => return Err(TokioUdpErrors::NoResponse),
                Err(e) => return Err(TokioUdpErrors::Elapsed(e))
            };

            let response = &buf[..len];
            match internal::check_response_id([response[0], response[1]], id) {
                true => {},
                false => return Err(TokioUdpErrors::IdResponseInvalid(id))
            }

            let dns_msg = match DnsMessage::decode_query(response) {
                Ok(v) => v,
                Err(e) => return Err(TokioUdpErrors::DecodeQueryErrors(e))
            };

            Ok(dns_msg)
        }

        #[derive(Debug)]
        pub enum TokioUdpErrors{
            SocketIo(std::io::Error),
            Elapsed(Elapsed),
            IdResponseInvalid(u16),
            CouldNotSendMessage,
            NoResponse,
            DecodeQueryErrors(DecodeQueryErrors)
        }

        impl Display for TokioUdpErrors {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    TokioUdpErrors::SocketIo(e) => write!(f, "{}", e),
                    TokioUdpErrors::Elapsed(e) => write!(f, "{}", e),
                    TokioUdpErrors::IdResponseInvalid(id) => write!(f,
                        "The DNS query's response ID didn't match with the DNS question sent.\nId: {}", id),
                    TokioUdpErrors::CouldNotSendMessage => write!(f, "Could not send the DNS message over UDP with any DNS name server from the server list"),
                    TokioUdpErrors::NoResponse => write!(f, "Could not get a DNS response from the DNS name server list."),
                    TokioUdpErrors::DecodeQueryErrors(e) => write!(f, "{}", e)
                }
            }
        }

        impl Error for TokioUdpErrors {}

        /// Represents high-level resolver errors exposed to users.
        #[derive(Debug)]
        pub enum ResolverErrorsAsync {
            SendingUdpQuery(TokioUdpErrors)
        }

        impl Display for ResolverErrorsAsync{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    ResolverErrorsAsync::SendingUdpQuery(e) => write!(f, "{}", e)
                }
            }
        }

        impl Error for ResolverErrorsAsync {}

        impl From<std::io::Error> for TokioUdpErrors {
            fn from(value: std::io::Error) -> Self {
                TokioUdpErrors::SocketIo(value)
            }
        }
    }
}
