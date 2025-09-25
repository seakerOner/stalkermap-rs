//! # StalkerMap
//!
//! A comprehensive Rust library for building CLI network scanner applications with robust input validation,
//! terminal interaction, and URL parsing capabilities.
//!
//! ## Overview
//!
//! StalkerMap provides the foundational utilities needed to create interactive command-line
//! network scanning tools. The library emphasizes safety, performance, and ease of use through
//! Rust's type system and zero-dependency design.
//!
//! ## Features
//!
//!  Currently Available
//!
//! - **Input Sanitization & Validation** - Type-safe input validation with composable filters
//! - **Interactive Terminal Interface** - User-friendly CLI input with validation loops
//! - **URL Parsing** - Comprehensive HTTP/HTTPS URL parsing with host validation
//!
//!  Planned Features
//!
//! - **DNS Queries** - Resolve hostnames and perform DNS lookups
//! - **Port Scanning** - Efficient port scanning with customizable options
//! - **Directory Enumeration** - Web directory and file discovery
//! - **Report Generation** - Export scan results to various formats
//!
//! ## Quick Start
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! stalkermap = "0.1.0"
//! ```
//!
//! ## Usage Examples
//!
//! ### Basic Input Validation
//!
//! ```rust,no_run
//! use stalkermap::utils::{Terminal, Sanitize, DesiredType};
//!
//! // Get validated user input
//! let user_input = Terminal::ask(
//!     "Enter target URL:",
//!     &[Sanitize::IsType(DesiredType::String)],
//! );
//! println!("Target: {}", user_input.answer);
//! ```
//!
//! ### URL Parsing and Validation
//!
//! ```rust,no_run
//! use stalkermap::utils::UrlParser;
//!
//! // Parse and validate URLs
//! match UrlParser::new("https://example.com:8080/api") {
//!     Ok(url) => {
//!         println!("Scheme: {}", url.scheme);
//!         println!("Target: {}", url.target);
//!         println!("Port: {}", url.port);
//!         println!("Path: {}", url.subdirectory);
//!     }
//!     Err(e) => eprintln!("Invalid URL: {}", e),
//! }
//! ```
//!
//! ### Complex Input Validation
//!
//! ```rust,no_run
//! use stalkermap::utils::{Terminal, Sanitize, DesiredType};
//!
//! // Multiple validation rules
//! let choice = Terminal::ask(
//!     "Choose scan type (quick/deep/custom):",
//!     &[
//!         Sanitize::IsType(DesiredType::String),
//!         Sanitize::MatchStrings(vec![
//!             "quick".to_string(),
//!             "deep".to_string(),
//!             "custom".to_string(),
//!         ]),
//!     ],
//! );
//! ```
//!
//! ### Complete Interactive URL Input Example
//!
//! This example demonstrates the complete workflow of getting user input, validating it,
//! and parsing URLs - perfect for network scanner applications:
//!
//! ```rust,no_run
//! use stalkermap::utils::{Terminal, Sanitize, DesiredType, UrlParser};
//!
//! fn main() {
//!     // Get URL from user with validation
//!     let url: UrlParser = loop {
//!         let input = Terminal::ask(
//!             "Enter a URL (http:// or https://):",
//!             &[Sanitize::IsType(DesiredType::String)],
//!         );
//!
//!         // Parse and validate the URL
//!         match UrlParser::new(&input.answer) {
//!             Ok(url) => break url,
//!             Err(e) => println!("{}", e)
//!         }
//!     };
//!
//!     println!("Full url:{}", url.full_url);
//!     println!("{}", url);
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is designed with modularity and composability in mind:
//!
//! - **`utils`** - Core utilities for input handling and URL parsing
//! - **`dns`** - DNS resolution and query utilities (planned)
//! - **`scanner`** - Port scanning and network discovery (planned)
//! - **`reporter`** - Report generation and export (planned)
//!
//! ## Design Principles
//!
//! - **Zero Dependencies** - Uses only Rust standard library for maximum compatibility
//! - **Type Safety** - Leverages Rust's type system for compile-time guarantees
//! - **Error Handling** - Comprehensive error types with descriptive messages
//! - **Performance** - Optimized for speed and memory efficiency
//! - **Usability** - Intuitive APIs with excellent documentation
//!
//! ## Supported URL Formats
//!
//! - HTTP/HTTPS schemes
//! - IPv4 and IPv6 addresses
//! - DNS hostnames
//! - Custom ports
//! - Paths and query strings
//!
//! ## Error Handling
//!
//! All operations return `Result<T, E>` types for safe error handling:
//!
//! ```rust,no_run
//! use stalkermap::utils::{UrlParser, UrlParserErrors};
//!
//! match UrlParser::new("invalid-url") {
//!     Ok(url) => println!("Valid URL: {}", url),
//!     Err(UrlParserErrors::InvalidScheme) => eprintln!("Only HTTP/HTTPS supported"),
//!     Err(UrlParserErrors::InvalidTargetType) => eprintln!("Invalid hostname or IP"),
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//! ```
//!
//! ## Contributing
//!
//! Contributions are welcome! Please see the [GitHub repository](https://github.com/yourusername/stalkermap-rs)
//! for contribution guidelines.
//!
//! ## License
//!
//! This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
//!
//! ## Changelog
//!
//! See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.

pub mod utils;
