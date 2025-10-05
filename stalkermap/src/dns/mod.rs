//! # Stalkermap DNS Library
//!
//! A lightweight and flexible DNS library written in pure Rust. It provides tools
//! for building custom resolvers, scanners, or network tools that require DNS support.
//!
//! The library is split into features that allow you to choose the level of functionality:
//!
//! ## Features
//!
//! - **Agnostic (`agnostic`)**
//!   - Pure DNS message parsing, encoding, and decoding.
//!   - No built-in transport or async runtime; you can plug in your own.
//!   - Lightweight and fast, ideal for advanced use cases or custom scanning pipelines.
//!
//! - **Standard (`std`)**
//!   - Blocking resolver using `std::net` (UDP/TCP).
//!   - Full synchronous DNS resolution with common record types (A, AAAA, CNAME, MX, TXT, etc.).
//!   - Simple and easy to use, recommended for most users who don’t need async.
//!
//! - **Tokio (`tokio-dep`)**
//!   - Async resolver using `tokio::net`. (Planned)
//!   - Supports non-blocking queries, TCP fallback, retries, and EDNS(0). (Planned)
//!   - Allows building high-performance async scanners and network tools. (Planned)
//!
//! ## Modules
//!
//! - `resolver` — High-level API for sending queries and resolving DNS records.
//! - `compressor` — Handles name compression and message encoding/decoding.
//! - `transporter` — Utilities for managing DNS server lists and transport details.
//!
//! ## Quick Example
//!
//! ```rust,ignore
//! use stalkermap::dns::resolver::resolve_ipv4;
//!
//! match resolve_ipv4("example.com") {
//!     Ok(response) => {
//!         for answer in response.answer {
//!             println!("IPv4: {:?}", answer);
//!         }
//!     }
//!     Err(e) => eprintln!("DNS resolution failed: {e}"),
//! }
//! ```
//!
//! ## Documentation Notes
//!
//! - All public functions are included in docs except for `agnostic` where network operations
//!   are not applicable.
//! - Internal types such as `UdpErrors`, `ResolverErrors`, and `DecodeQueryErrors` are
//!   documented and implement `Display` and `Error` for easier integration.
//!
//! For advanced usage, RFC references and roadmap can be found in `docs/DNSROADMAP.md`.

cfg_if::cfg_if! {
    if #[cfg(any( feature = "std", doc))]  {
        pub mod resolver;
    } else if #[cfg(any(feature = "tokio-dep", doc))] {
        pub mod resolver;
    } else if #[cfg(any(feature = "agnostic", doc))] {
        pub mod resolver;
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(feature = "std", feature = "tokio-dep"))] {
        mod compressor;
    } else if #[cfg(feature = "agnostic")] {
        pub mod compressor;
    } else if #[cfg(doc)] {
        // Only for documentation builds
        pub mod compressor;
    }
}

//#[cfg(any(feature = "std", feature = "tokio-dep", doc))]
//mod compressor;

//#[cfg(feature = "agnostic")]
//pub mod compressor;
