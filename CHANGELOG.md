# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Planned
- DNS queries and hostname resolution
- Port scanning (TCP/UDP)
- Directory enumeration for web applications
- Report generation (JSON, XML, CSV)

## [0.1.3] - 05-10-2025
### Added

- **All versions**
  - DNS transport layer:
    - `get_servers()`, `has_custom_servers()`, `reset_servers()`, `set_servers()`.

- **"std" and "tokio-dep" features**
  - Blocking resolver functions:
    - `resolve_ipv4()`, `resolve_cname()`, `resolve_hinfo()`, `resolve_minfo()`, `resolve_mx()`, `resolve_ptr()`, `resolve_soa()`, `resolve_txt()`, `resolve_wks()`.
  - Internal function `send_query_blocking()` for UDP queries.

### Technical Notes
- DNS transport layer added for all versions.
- Resolver now supports multiple record types via blocking UDP queries.
- Documentation includes all public functions for all features except `agnostic`, using stubs for types where needed.
- Error handling refined with structured types (`UdpErrors`, `ResolverErrors`, `DecodeQueryErrors`).

## [0.1.2] - 30-09-2025
### Added 
The current release provides message construction and encoding. Decoding and message transport helpers are planned for a future release.
- (All versions)
  - Expanded internal documentation across DNS message types and helpers
  - Unit tests for record encoding/decoding and header flag conversions
- ("Agnostic" feature)
  - `DnsMessage::new_query` for constructing standard queries
  - `DnsMessage::encode_query` for serializing queries into raw bytes
  - `DnsHeaderFlags` with encode/decode helpers
  - `RecordType` enum with `to_bytes` encoding
  - Additional resource record structs: `AnswerSection`, `AuthoritySection`, `AdditionalSection`

### Technical Notes
- Introduced `rand` dependency to generate random 16-bit DNS IDs
- Internal API stability note:
  While exposed under the `agnostic` feature, low-level DNS types are considered advanced APIs and may change in minor versions

## [0.1.1] - 29-09-2025
### Added 
- (All versions)
  - Enhanced `DesiredType` in Utils by implementing `FromStr` and `TryFrom` traits
- ("Agnostic" feature)
  - Added low-level DNS message structure
  - Added DNS message compressor for hostnames (RFC1035 compliant)

### Technical Notes
- Added 3 new versions: `std`, `tokio-dep`, `agnostic`
  - Currently, none have special features enabled by default
  - The "agnostic" version exposes internal DNS structures for advanced users
  - All new features in the "agnostic" version are internal; they will be abstracted in `std` and `tokio-dep` versions for simpler usage

## [0.1.0] - 26-09-2025
### Added
- Input validation with `Sanitize` enum
  - Type checking for primitives (`DesiredType`)
  - String matching (`MatchString`, `MatchStrings`)
  - Range validation (`IsBetween`)
- Interactive terminal interface (`Terminal::ask`)
- URL parsing (`UrlParser`) for HTTP/HTTPS
  - IPv4, IPv6, and DNS hostname support
  - Port and path parsing
- Zero dependencies (std library only)
- Comprehensive test suite
- Module documentation with examples

### Technical Notes
- Custom error types with descriptive messages
- Composable validation filters
- Multiple URL creation methods (`new`, `FromStr`, `TryFrom`)
