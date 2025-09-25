# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Planned
- DNS queries and hostname resolution
- Port scanning (TCP/UDP)
- Directory enumeration for web applications
- Report generation (JSON, XML, CSV)

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
