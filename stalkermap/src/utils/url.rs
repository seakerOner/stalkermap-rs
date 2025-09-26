//! # UrlParser
//!
//! A minimal and safe URL parser in Rust.
//!
//! **Features:**
//! - Supports `http` and `https` schemes
//! - Host validation (`DNS`, `IPv4`, `IPv6`)
//! - Custom error enum for precise error handling
//! - No external dependencies
//!
//! ## Example
//!
//! ```rust,no_run
//! use std::str::FromStr;
//! use std::convert::TryFrom;
//! use stalkermap::utils::UrlParser;
//!
//! // Via `new` constructor (returns Result)
//! let url = UrlParser::new("<https://example.com>").unwrap();
//!
//! // Via `parse` using FromStr (returns Result)
//! let url2: UrlParser = "<https://example.com>".parse().unwrap();
//!
//! // Via TryFrom (returns Result)
//! let url3 = UrlParser::try_from("<https://example.com>").unwrap();
//!
//! // Note: `From<&str>` is intentionally not implemented, because parsing may fail.
//! // Users should use `new`, `parse`, or `TryFrom` for safe URL creation.
//! ```
use std::str::FromStr;
use std::{
    error::Error,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Represents a parsed URL.
///
/// Contains information about:
/// - [`Scheme`] (`http` or `https`)
/// - [`TargetType`] (DNS, IPv4, IPv6)
/// - Associated port (0 is the default and its not included on the url)
/// - Full normalized URL
#[derive(Debug, PartialEq)]
pub struct UrlParser {
    pub scheme: Scheme,
    pub target: String,
    pub target_type: TargetType,
    pub port: u16,
    pub subdirectory: String,
    pub full_url: String,
}

impl Display for UrlParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Scheme: {}\nTarget: {}\nTarget type: {}\nPort: {}\nSub directory: {}\nFull url: {}",
            self.scheme, self.target, self.target_type, self.port, self.subdirectory, self.full_url
        )
    }
}

/// Represents the scheme of a URL (`http` or `https`).
#[derive(Debug, PartialEq)]
pub enum Scheme {
    Http,
    Https,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
        }
    }
}

/// Represents the type of the host/target.
///
/// Can be:
/// - `Dns`
/// - `IPv4`
/// - `IPv6`
#[derive(Debug, PartialEq)]
pub enum TargetType {
    Dns,
    IPv4,
    IPv6,
}

impl Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns => write!(f, "dns"),
            Self::IPv4 => write!(f, "ipv4"),
            Self::IPv6 => write!(f, "ipv6"),
        }
    }
}

impl TargetType {
    /// Checks if the provided string is a valid DNS.
    ///
    /// # Rules
    /// - Maximum length: 253 characters
    /// - Each label ≤ 63 characters
    /// - Cannot start or end with `-`
    /// - Only ASCII alphanumeric characters and `-` allowed
    pub fn is_dns(target: &str) -> Result<TargetType, UrlParserErrors> {
        if target.len() > 253 {
            return Err(UrlParserErrors::InvalidTargetType);
        }

        let valid: bool = target.split('.').all(|label| {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }

            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }

            true
        });

        if valid {
            Ok(TargetType::Dns)
        } else {
            Err(UrlParserErrors::InvalidTargetType)
        }
    }

    /// Checks if the provided string is a valid IPv4 address.
    pub fn is_ipv4(target: &str) -> Result<TargetType, UrlParserErrors> {
        match Ipv4Addr::from_str(target) {
            Ok(_) => Ok(TargetType::IPv4),
            Err(_) => Err(UrlParserErrors::InvalidTargetType),
        }
    }

    /// Checks if the provided string is a valid IPv6 address.
    pub fn is_ipv6(target: &str) -> Result<TargetType, UrlParserErrors> {
        let clean_ip = target.trim_matches(['[', ']'].as_ref());
        match Ipv6Addr::from_str(clean_ip) {
            Ok(_) => Ok(TargetType::IPv6),
            Err(_) => Err(UrlParserErrors::InvalidTargetType),
        }
    }
}

/// Represents possible errors when parsing a URL.
#[derive(Debug)]
pub enum UrlParserErrors {
    UrlEmpty,
    InvalidSize,
    InvalidScheme,
    InvalidTargetType,
    InvalidSchemeSyntax,
    InvalidPort,
}

impl Display for UrlParserErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UrlEmpty => {
                write!(f, "The url is empty")
            }
            Self::InvalidSize => {
                write!(f, "Invalid size!")
            }
            Self::InvalidScheme => {
                write!(f, "Invalid scheme => http or https")
            }
            Self::InvalidTargetType => {
                write!(f, "Invalid target type => Must be a DNS or IPV4 OR IPV6")
            }
            Self::InvalidSchemeSyntax => {
                write!(f, "Invalid scheme sintax => http:// or https://")
            }
            Self::InvalidPort => {
                write!(f, "Invalid port => (1 -> 65,535)")
            }
        }
    }
}

impl Error for UrlParserErrors {}

/// Helper macro to safely slice a string with error handling.
///
/// subslice!({input}, {range}, {ErrorMessage})
///
/// # Example
/// ```rust,ignore
///
/// let s = "<https://example.com>";
/// let scheme = subslice!(s, ..5, UrlParserErrors::InvalidSize);
/// ```
#[macro_export]
macro_rules! subslice {
    ($s:expr, $slice:expr, $err:expr) => {
        $s.get($slice).ok_or($err)?
    };
}

impl std::str::FromStr for UrlParser {
    type Err = UrlParserErrors;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UrlParser::new(s)
    }
}

impl TryFrom<&str> for UrlParser {
    type Error = UrlParserErrors;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        UrlParser::new(value)
    }
}

impl UrlParser {
    /// Creates a new [`UrlParser`] from a `Terminal` input.
    ///
    /// # Errors
    /// Returns [`UrlParserErrors`] if:
    /// - The scheme is invalid
    /// - The host is invalid
    /// - The URL is empty
    ///
    /// # Example
    ///  ```rust,no_run
    /// use stalkermap::utils::UrlParser;
    ///
    /// // Safe creation via `new`
    /// let url = UrlParser::new("<http://example.com>").unwrap();
    /// assert_eq!(url.full_url, "<http://example.com>");
    ///
    /// // Also usable via `parse` (FromStr) or `TryFrom`
    /// let url2: UrlParser = "<http://example.com>".parse().unwrap();
    /// let url3 = UrlParser::try_from("<http://example.com>").unwrap();
    /// ```
    pub fn new(input_url: &str) -> Result<UrlParser, UrlParserErrors> {
        let url = input_url;

        if url.is_empty() {
            return Err(UrlParserErrors::UrlEmpty);
        }

        if subslice!(&url, ..7, UrlParserErrors::InvalidSize) != "http://"
            && subslice!(&url, ..8, UrlParserErrors::InvalidSize) != "https://"
        {
            return Err(UrlParserErrors::InvalidSchemeSyntax);
        }

        let scheme = if url.starts_with("http://") {
            Scheme::Http
        } else if url.starts_with("https://") {
            Scheme::Https
        } else {
            return Err(UrlParserErrors::InvalidScheme);
        };

        let target: String = {
            match scheme {
                Scheme::Http => {
                    if url[7..].starts_with('[') {
                        url[7..]
                            .chars()
                            .take_while(|c| *c != ']')
                            .chain(std::iter::once(']'))
                            .collect()
                    } else {
                        url.chars()
                            .skip(7)
                            .take_while(|c| *c != ':' && *c != '/')
                            .collect()
                    }
                }
                Scheme::Https => {
                    if url[8..].starts_with('[') {
                        url[8..]
                            .chars()
                            .take_while(|c| *c != ']')
                            .chain(std::iter::once(']'))
                            .collect()
                    } else {
                        url.chars()
                            .skip(8)
                            .take_while(|c| *c != ':' && *c != '/')
                            .collect()
                    }
                }
            }
        };

        let target_type: TargetType = TargetType::is_ipv4(&target)
            .or(TargetType::is_ipv6(&target))
            .or(TargetType::is_dns(&target))?;

        let quant_to_skip = match scheme {
            Scheme::Http => "http://".len() + target.len(),
            Scheme::Https => "https://".len() + target.len(),
        };

        let port: u16 = {
            if quant_to_skip >= url.len() {
                0
            } else if url
                .chars()
                .nth(quant_to_skip)
                .ok_or(UrlParserErrors::InvalidSize)?
                == ':'
            {
                let string_port_temp: String = url
                    .chars()
                    .skip(quant_to_skip + 1)
                    .take_while(|v| v.is_ascii_digit())
                    .collect();

                match string_port_temp.parse::<u16>() {
                    Ok(port) => port,
                    Err(_) => return Err(UrlParserErrors::InvalidPort),
                }
            } else {
                0
            }
        };

        let subdirectory = {
            let chars_to_skip = {
                match scheme {
                    Scheme::Http => "http://".len(),
                    Scheme::Https => "https://".len(),
                }
            } + target.len()
                + {
                    match port {
                        0 => 0,
                        n => format!(":{}", n).len(),
                    }
                };
            let subdirectory: String = url.chars().skip(chars_to_skip).collect();
            subdirectory
        };

        let full_url = format!(
            "{}://{}{}{}",
            scheme,
            target,
            match port {
                0 => String::new(),
                n => format!(":{}", n),
            },
            subdirectory
        );

        Ok(UrlParser {
            scheme,
            target,
            target_type,
            port,
            subdirectory,
            full_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_urlparser_valid_http_dns() {
        let url = UrlParser::new("http://example.com").unwrap();
        assert_eq!(format!("{}", url.scheme), "http");
        assert_eq!(url.target, "example.com");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 0);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "http://example.com");
        assert_ne!(
            url.to_string(),
            "Scheme: http Target: example.com Target type: dns Port: 0 Sub directory: Full url: http://example.com"
        );
    }

    #[test]
    fn test_url_urlparser_valid_https_dns_with_path() {
        let url = UrlParser::new("https://example.com/test/path").unwrap();
        assert_eq!(format!("{}", url.scheme), "https");
        assert_eq!(url.target, "example.com");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 0);
        assert_eq!(url.subdirectory, "/test/path");
        assert_eq!(url.full_url, "https://example.com/test/path");
        assert_ne!(
            url.to_string(),
            "Scheme: https Target: example.com Target type: dns Port: 0 Sub directory: /test/path Full url: https://example.com/test/path"
        );
    }

    #[test]
    fn test_url_urlparser_valid_https_dns_with_port_and_path() {
        let url = UrlParser::new("https://example.com:420/test/path").unwrap();
        assert_eq!(format!("{}", url.scheme), "https");
        assert_eq!(url.target, "example.com");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 420);
        assert_eq!(url.subdirectory, "/test/path");
        assert_eq!(url.full_url, "https://example.com:420/test/path");
        assert_ne!(
            url.to_string(),
            "Scheme: https Target: example.com Target type: dns Port: 420 Sub directory: /test/path Full url: https://example.com:420/test/path"
        );
    }

    #[test]
    fn test_url_urlparser_valid_http_with_port() {
        let url = UrlParser::new("http://localhost:8080").unwrap();
        assert_eq!(format!("{}", url.scheme), "http");
        assert_eq!(url.target, "localhost");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 8080);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "http://localhost:8080");
        assert_ne!(
            url.to_string(),
            "Scheme: http Target: localhost Target type: dns Port: 8080 Sub directory: Full url: http://localhost:8080"
        );
    }

    #[test]
    fn test_url_urlparser_valid_ipv4() {
        let url = UrlParser::new("http://127.0.0.1").unwrap();
        assert_eq!(format!("{}", url.scheme), "http");
        assert_eq!(url.target, "127.0.0.1");
        assert_eq!(format!("{}", url.target_type), "ipv4");
        assert_eq!(url.port, 0);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "http://127.0.0.1");
        assert_ne!(
            url.to_string(),
            "Scheme: http Target: 127.0.0.1 Target type: ipv4 Port: 0 Sub directory: Full url: http://127.0.0.1"
        );
    }

    #[test]
    fn test_url_urlparser_valid_ipv6() {
        let url = UrlParser::new("https://[::1]").unwrap();
        assert_eq!(format!("{}", url.scheme), "https");
        assert_eq!(url.target, "[::1]");
        assert_eq!(format!("{}", url.target_type), "ipv6");
        assert_eq!(url.port, 0);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "https://[::1]");
        assert_ne!(
            url.to_string(),
            "Scheme: https Target: [::1] Target type: ipv6 Port: 0 Sub directory: Full url: https://[::1]"
        );
    }

    #[test]
    fn test_url_urlparser_direct_parse() {
        let url = "https://example.com:33".parse::<UrlParser>().unwrap();
        assert_eq!(format!("{}", url.scheme), "https");
        assert_eq!(url.target, "example.com");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 33);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "https://example.com:33");
        assert_ne!(
            url.to_string(),
            "Scheme: https Target: example.com Target type: dns Port: 33 Sub directory: Full url: https://example.com:33"
        );
    }

    #[test]
    fn test_url_urlparser_direct_parse_try_from() {
        let url = UrlParser::try_from("http://example.com").unwrap();
        assert_eq!(format!("{}", url.scheme), "http");
        assert_eq!(url.target, "example.com");
        assert_eq!(format!("{}", url.target_type), "dns");
        assert_eq!(url.port, 0);
        assert_eq!(url.subdirectory, "");
        assert_eq!(url.full_url, "http://example.com");
        assert_ne!(
            url.to_string(),
            "Scheme: http Target: example.com Target type: dns Port: 0 Sub directory: Full url: https://example.com"
        );
    }

    #[test]
    fn test_url_urlparser_invalid_empty_url() {
        let res = UrlParser::new("");
        assert!(matches!(res, Err(UrlParserErrors::UrlEmpty)));
    }

    #[test]
    fn test_url_urlparser_invalid_scheme() {
        let res = UrlParser::new("ftp://example.com");
        assert!(matches!(res, Err(UrlParserErrors::InvalidSchemeSyntax)));
    }

    #[test]
    fn test_url_urlparser_invalid_dns() {
        let res = UrlParser::new("http://exa$mple.com");
        assert!(matches!(res, Err(UrlParserErrors::InvalidTargetType)));
    }

    #[test]
    fn test_url_urlparser_invalid_port_not_number() {
        let res = UrlParser::new("http://example.com:abcd");
        assert!(matches!(res, Err(UrlParserErrors::InvalidPort)));
    }

    #[test]
    fn test_url_urlparser_invalid_port_out_of_range() {
        let res = UrlParser::new("http://example.com:70000");
        assert!(matches!(res, Err(UrlParserErrors::InvalidPort)));
    }
}
