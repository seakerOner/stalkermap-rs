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
/// - Associated port
/// - Full normalized URL
pub struct UrlParser {
    scheme: Scheme,
    target: String,
    target_type: TargetType,
    port: u16,
    subdirectory: String,
    full_url: String,
}

impl Display for UrlParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Scheme:{}\nTarget:{}\nTarget type:{}\nPort:{}\nSub directory:{}\nFull url:{}",
            self.scheme, self.target, self.target_type, self.port, self.subdirectory, self.full_url
        )
    }
}

/// Represents the scheme of a URL (`http` or `https`).
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
        match Ipv6Addr::from_str(target) {
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

impl From<()> for UrlParserErrors {
    fn from(_value: ()) -> Self {
        UrlParserErrors::InvalidTargetType
    }
}

/// Helper macro to safely slice a string with error handling.
///
/// subslice!({input}, {range}, {ErrorMessage})
///
/// # Example
/// ```rust,ignore
/// let s = "https://example.com";
/// let scheme = subslice!(s, ..5, UrlParserErrors::InvalidSize);
/// ```

#[macro_export]
macro_rules! subslice {
    ($s:expr, $slice:expr, $err:expr) => {
        $s.get($slice).ok_or($err)?
    };
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
                Scheme::Http => url
                    .chars()
                    .skip(7)
                    .take_while(|c| *c != ':' && *c != '/')
                    .collect(),
                Scheme::Https => url
                    .chars()
                    .skip(8)
                    .take_while(|c| *c != ':' && *c != '/')
                    .collect(),
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
            } else {
                if url
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

                    let valid_port = match string_port_temp.parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => return Err(UrlParserErrors::InvalidPort),
                    };
                    valid_port
                } else {
                    0
                }
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
