//! # StalkerMap Core Utilities
//!
//! A comprehensive toolkit for building interactive CLI applications with robust input validation,
//! terminal interaction, and URL parsing capabilities.
//!
//! ## Overview
//!
//! This crate provides three main utilities for CLI application development:
//!
//! 1. **Input Sanitization & Validation** - Validate user input with type checking and custom rules
//! 2. **Interactive Terminal Interface** - Prompt users with validation loops until valid input is received
//! 3. **URL Parsing** - Parse and validate HTTP/HTTPS URLs with comprehensive error handling
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType, UrlParser};
//!
//! // Get validated user input
//! let user_input = Terminal::ask(
//!     "Enter your age:",
//!     &[Sanitize::IsType(DesiredType::U8)],
//! );
//!
//! // Parse a URL
//! let url = UrlParser::new("https://example.com").unwrap();
//! println!("Parsed URL: {}", url);
//! ```
//!
//! ## Core Components
//!
//! ### 1. Input Sanitization (`Sanitize`)
//!
//! The `Sanitize` enum provides flexible input validation with three main strategies:
//!
//! - **Type Validation**: Ensure input can be parsed as specific Rust types
//! - **Exact String Matching**: Require input to match a specific string
//! - **Multiple Option Matching**: Allow input to match one of several valid options
//!
//! #### Type Validation Examples
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Sanitize, DesiredType};
//!
//! // Validate as boolean
//! let bool_filter = Sanitize::IsType(DesiredType::Bool);
//!
//! // Validate as unsigned 8-bit integer
//! let number_filter = Sanitize::IsType(DesiredType::U8);
//!
//! // Validate as signed 32-bit integer
//! let signed_filter = Sanitize::IsType(DesiredType::I32);
//! ```
//!
//! #### String Matching Examples
//!
//! ```rust,no_run
//! use stalkermap_core::utils::Sanitize;
//!
//! // Exact string match
//! let exact_match = Sanitize::MatchString("yes".to_string());
//!
//! // Multiple valid options
//! let options = Sanitize::MatchStrings(vec![
//!     "yes".to_string(),
//!     "no".to_string(),
//!     "y".to_string(),
//!     "n".to_string(),
//! ]);
//! ```
//!
//! #### Supported Types
//!
//! The `DesiredType` enum supports all common Rust primitive types:
//!
//! - **Strings**: `DesiredType::String`
//! - **Booleans**: `DesiredType::Bool`
//! - **Unsigned Integers**: `U8`, `U16`, `U32`, `U64`, `U128`
//! - **Signed Integers**: `I8`, `I16`, `I32`, `I64`, `I128`
//!
//! ### 2. Interactive Terminal Interface (`Terminal`)
//!
//! The `Terminal` struct provides a user-friendly way to collect validated input from users.
//! It automatically handles the validation loop, displaying helpful error messages until valid input is received.
//!
//! #### Basic Usage
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType};
//!
//! // Simple boolean input
//! let response = Terminal::ask(
//!     "Do you want to continue? (true/false)",
//!     &[Sanitize::IsType(DesiredType::Bool)],
//! );
//! println!("User response: {}", response.answer);
//! ```
//!
//! #### Complex Validation
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType};
//!
//! // Multiple validation rules
//! let choice = Terminal::ask(
//!     "Choose an option (A, B, or C):",
//!     &[
//!         Sanitize::IsType(DesiredType::String),
//!         Sanitize::MatchStrings(vec![
//!             "A".to_string(),
//!             "B".to_string(),
//!             "C".to_string(),
//!         ]),
//!     ],
//! );
//! ```
//!
//! #### Error Handling
//!
//! The terminal automatically handles validation errors and provides user-friendly messages:
//!
//! - Type validation errors: "The value is not a u8, try again!"
//! - String matching errors: "The value doesn't match with yes, try again!"
//! - Multiple option errors: "The value doesn't match with the options: A, B, C, try again!"
//!
//! ### 3. URL Parsing (`UrlParser`)
//!
//! The `UrlParser` provides safe and comprehensive URL parsing for HTTP and HTTPS URLs.
//! It supports various host types and provides detailed error information.
//!
//! #### Supported URL Formats
//!
//! - **HTTP URLs**: `http://example.com`, `http://127.0.0.1:8080`
//! - **HTTPS URLs**: `https://example.com`, `https://[::1]:443`
//! - **With Ports**: `http://localhost:3000`, `https://api.example.com:8443`
//! - **With Paths**: `https://example.com/api/v1/users`
//! - **IPv4 Addresses**: `http://192.168.1.1`
//! - **IPv6 Addresses**: `https://[2001:db8::1]`
//!
//! #### Basic Usage
//!
//! ```rust,no_run
//! use stalkermap_core::utils::UrlParser;
//!
//! // Parse a URL
//! match UrlParser::new("https://example.com/api/users") {
//!     Ok(url) => {
//!         println!("Scheme: {}", url.scheme);
//!         println!("Target: {}", url.target);
//!         println!("Port: {}", url.port);
//!         println!("Path: {}", url.subdirectory);
//!         println!("{}", url);
//!     }
//!     Err(e) => eprintln!("Invalid URL: {}", e),
//! }
//! ```
//!
//! #### Alternative Creation Methods
//!
//! ```rust,no_run
//! use stalkermap_core::utils::UrlParser;
//! use std::str::FromStr;
//! use std::convert::TryFrom;
//!
//! // Method 1: Using new()
//! let url1 = UrlParser::new("https://example.com").unwrap();
//!
//! // Method 2: Using FromStr
//! let url2: UrlParser = "https://example.com".parse().unwrap();
//!
//! // Method 3: Using TryFrom
//! let url3 = UrlParser::try_from("https://example.com").unwrap();
//! ```
//!
//! #### URL Components
//!
//! The `UrlParser` struct provides access to all URL components:
//!
//! - `scheme`: HTTP or HTTPS
//! - `target`: The hostname or IP address
//! - `target_type`: DNS, IPv4, or IPv6
//! - `port`: Port number (0 for default)
//! - `subdirectory`: Path and query string
//! - `full_url`: Complete normalized URL
//!
//! #### Error Handling
//!
//! The `UrlParserErrors` enum provides specific error types:
//!
//! - `UrlEmpty`: Empty URL provided
//! - `InvalidScheme`: Unsupported scheme (only HTTP/HTTPS allowed)
//! - `InvalidSchemeSyntax`: Malformed scheme syntax
//! - `InvalidTargetType`: Invalid hostname or IP address
//! - `InvalidPort`: Port out of range (1-65535)
//! - `InvalidSize`: URL too short for parsing
//!
//! ## Complete Example: Interactive URL Input
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType, UrlParser};
//!
//! fn main() {
//!    let url = loop {
//!       // Get URL from user with validation
//!       let input = Terminal::ask(
//!          "Enter a URL (http:// or https://):",
//!          &[Sanitize::IsType(DesiredType::String)],
//!       );
//!
//!       // Parse and validate the URL
//!       match UrlParser::new(&input.answer) {
//!          Ok(url) => break url,
//!          Err(e) => eprintln!("{}", e)
//!       }
//!    };
//! }
//! ```
//!
//! ## Advanced Usage Patterns
//!
//! ### Combining Multiple Validations
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType};
//!
//! // Validate that input is a number AND within a specific range
//! let age_input = Terminal::ask(
//!     "Enter your age (18-65):",
//!     &[
//!         Sanitize::IsType(DesiredType::U8),
//!         // You could add custom range validation here
//!     ],
//! );
//!
//! // Parse the validated input
//! let age: u8 = age_input.answer.parse().unwrap();
//! ```
//!
//! ### Case-Insensitive String Matching
//!
//! ```rust,no_run
//! use stalkermap_core::utils::{Terminal, Sanitize, DesiredType};
//!
//! let response = Terminal::ask(
//!     "Continue? (yes/no):",
//!     &[
//!         Sanitize::IsType(DesiredType::String),
//!         Sanitize::MatchStrings(vec![
//!             "yes".to_string(),
//!             "no".to_string(),
//!             "YES".to_string(),
//!             "NO".to_string(),
//!             "y".to_string(),
//!             "n".to_string(),
//!         ]),
//!     ],
//! );
//! ```
//!
//! ## Best Practices
//!
//! 1. **Always use validation**: Never trust user input without validation
//! 2. **Provide clear prompts**: Make it obvious what format you expect
//! 3. **Handle errors gracefully**: Use the provided error types for specific error handling
//! 4. **Combine validations**: Use multiple `Sanitize` filters for complex validation rules
//! 5. **Test edge cases**: Validate with various input types and edge cases
//!
//! ## Dependencies
//!
//! This crate has minimal dependencies and focuses on core functionality:
//! - Standard library only for most functionality
//! - No external HTTP clients or networking libraries
//! - Pure Rust implementation for maximum compatibility

pub mod sanitize;
pub use sanitize::{DesiredType, Sanitize};

pub mod terminal;
pub use terminal::Terminal;

pub mod url;
pub use url::{TargetType, UrlParser, UrlParserErrors};
