# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Planned
- DNS queries and hostname resolution
- Port scanning (TCP/UDP)
- Directory enumeration for web applications
- Report generation (JSON, XML, CSV)

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
