# StalkerMap

A comprehensive Rust library for building CLI network scanner applications with robust input validation, terminal interaction, and URL parsing capabilities.

[![Crates.io](https://img.shields.io/crates/v/stalkermap.svg)](https://crates.io/crates/stalkermap)
[![Documentation](https://docs.rs/stalkermap/badge.svg)](https://docs.rs/stalkermap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- For advanced users: see docs for **dns::resolver::agnostic** and **dns::compressor::agnostic**

### Currently Available

(All feature versions)
- **Input Sanitization & Validation** - Type-safe input validation with composable filters
- **Interactive Terminal Interface** - User-friendly CLI input with validation loops  
- **URL Parsing** - Comprehensive HTTP/HTTPS URL parsing with host validation

("std" feature)
- **DNS Resolver** — Blocking DNS queries supporting multiple record types (A, MX, TXT, SOA, PTR, WKS, etc.)

("tokio-dep" feature)
- **DNS Resolver** - Async DNS queries with support for multiple record types (A, MX, TXT, SOA, PTR, WKS, etc.)

("Agnostic" feature)
- **DNS message structure** — With encoder helpers (RFC1035 compliant)  
- **DNS message compressor** — For hostnames (RFC1035 compliant)  

### Planned Features
 
- **Port Scanning** - Efficient port scanning with customizable options
- **Directory Enumeration** - Web directory and file discovery
- **Report Generation** - Export scan results to various formats

## Feature Variants

- **Agnostic version**
  - Only parsing, encoding/decoding of DNS messages and helpers.  
  - No executor or transport included — user chooses their own.  
  - Lightweight and easy to integrate.  
  - Includes access to low-level DNS structures and helpers.

- **Default (`std`) version**
  - Blocking TCP/UDP transport using `std::net`.  
  - Fully functional DNS resolver for blocking queries.


- **Tokio (`async`) version**
  - Replaces blocking transport with `tokio::net` for async TCP/UDP.  
  - Supports non-blocking behaviors inspired by RFCs (TCP fallback, EDNS, retries, etc.). (Planned)

  
## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
stalkermap = { version = "0.1.4", features = ["std"]}
stalkermap = { version = "0.1.4", features = ["tokio-dep"]}
stalkermap = { version = "0.1.4", default-features = false, features = ["agnostic"]}
```

## Usage Examples

### DNS Resolver Example (std)

```rust,no_run

use stalkermap::dns::resolver::{resolve_ipv4, resolve_mx};

let a_records = resolve_ipv4("example.com").unwrap();
let mx_records = resolve_mx("example.com").unwrap();

println!("A records: {:#?}", a_records);
println!("MX records: {:#?}", mx_records);
```

### Basic Input & Range Validation

```rust,no_run
use stalkermap::utils::{Terminal, Sanitize, DesiredType};

// Get validated user input with range checking
let threads = Terminal::ask(
    "Enter scan threads (1-16):",
    &[Sanitize::IsBetween(1, 16)],
);
println!("Threads: {}", threads.answer);
```

### URL Parsing and Validation

```rust,no_run
use stalkermap::utils::UrlParser;

// Parse and validate URLs
match UrlParser::new("https://example.com:8080/api") {
    Ok(url) => {
        println!("Scheme: {}", url.scheme);
        println!("Target: {}", url.target);
        println!("Port: {}", url.port);
        println!("Path: {}", url.subdirectory);
    }
    Err(e) => eprintln!("Invalid URL: {}", e),
}
```

### Complex Input Validation

```rust,no_run
use stalkermap::utils::{Terminal, Sanitize, DesiredType};

// Multiple validation rules
let choice = Terminal::ask(
    "Choose scan type (quick/deep/custom):",
    &[
        Sanitize::IsType(DesiredType::String),
        Sanitize::MatchStrings(vec![
            "quick".to_string(),
            "deep".to_string(),
            "custom".to_string(),
        ]),
    ],
);
```

### Complete Interactive URL Input Example

This example demonstrates the complete workflow of getting user input, validating it, and parsing URLs - perfect for network scanner applications:

```rust,no_run
use stalkermap::utils::{Terminal, Sanitize, DesiredType, UrlParser};

fn main() {
    // Get URL from user with validation
    let url: UrlParser = loop {
        let input = Terminal::ask(
            "Enter a URL (http:// or https://):",
            &[Sanitize::IsType(DesiredType::String)],
        );

        // Parse and validate the URL
        match UrlParser::new(&input.answer) {
            Ok(url) => break url,
            Err(e) => println!("{}", e)
        }
    };

    println!("{}", url);
}
```

 ### "Agnostic" Only Feature DNS Compressor Example

 Users can either build a DNS message manually using their own structures
 or use the `DnsMessage` struct provided by this library. Example with a raw buffer:

 ```rust,no_run
 use std::collections::HashMap;
 use stalkermap::dns::compressor::MessageCompressor;

 let mut message = Vec::new();
 let mut pointer_map = HashMap::new();

 // Compress a domain name
 MessageCompressor::compress("www.example.com", &mut message, &mut pointer_map).unwrap();

 // Reusing the same domain (or suffix) inserts a pointer instead of repeating bytes
 MessageCompressor::compress("mail.example.com", &mut message, &mut pointer_map).unwrap();
 ```

 ### "Agnostic" Only Feature DNS Message Query Builder Example

 ```rust,no_run
 use stalkermap::dns::resolver::agnostic::{DnsMessage, RecordType, OpCodeOptions};

 // Build a query for example.com A record
 let msg = DnsMessage::new_query("example.com", RecordType::A, OpCodeOptions::StandardQuery);

 // Encode into raw bytes, ready to send via UDP/TCP
 let bytes = msg.encode_query();

 assert!(!bytes[12..].is_empty()); // includes header + question
 ```

## Architecture

The library is designed with modularity and composability in mind:

- **`utils`** - Core utilities for input handling and URL parsing
- **`dns`** - DNS resolution and query utilities (planned)
- **`scanner`** - Port scanning and network discovery (planned)
- **`reporter`** - Report generation and export (planned)

## Supported URL Formats

- HTTP/HTTPS schemes
- IPv4 and IPv6 addresses
- DNS hostnames
- Custom ports
- Paths and query strings

## Error Handling

All operations return `Result<T, E>` types for safe error handling:

```rust,no_run
use stalkermap::utils::{UrlParser, UrlParserErrors};

match UrlParser::new("invalid-url") {
    Ok(url) => println!("Valid URL: {}", url),
    Err(UrlParserErrors::InvalidScheme) => eprintln!("Only HTTP/HTTPS supported"),
    Err(UrlParserErrors::InvalidTargetType) => eprintln!("Invalid hostname or IP"),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## CLI Application

This repository also includes a CLI application demonstrating the library usage:

```bash
# Clone and run
git clone https://github.com/seakerOner/stalkermap-rs
cd stalkermap-rs
cargo run --bin stalkermap-cli
```

## Contributing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.

## Performance

## Documentation

- [API Documentation](https://docs.rs/stalkermap)
- [Changelog](CHANGELOG.md)
