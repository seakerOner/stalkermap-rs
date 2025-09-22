use crate::utils::sanitize::{DesiredType, Sanitize};
use crate::utils::terminal::Terminal;
use std::{
    error::Error,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

pub struct UrlParser {
    scheme: Scheme,
    target: String,
    target_type: TargetType,
    port: u16,
    full_url: String,
}

enum Scheme {
    Http,
    Https,
}

pub enum TargetType {
    Dns,
    IPv4,
    IPv6,
}

impl TargetType {
    pub fn is_dns(target: &str) -> Result<TargetType, ()> {}
    pub fn is_ipv4(target: &str) -> Result<TargetType, ()> {}
    pub fn is_ipv6(target: &String) -> Result<TargetType, ()> {}
}

#[derive(Debug)]
enum UrlParserErrors {
    UrlEmpty,
    InvalidSize,
    InvalidScheme,
    InvalidTargetType,
    InvalidSchemeSintax,
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
            Self::InvalidSchemeSintax => {
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

macro_rules! subslice {
    ($v:expr, $slice:expr, $err:expr) => {
        $v.get($slice).ok_or($err)?
    };
}

impl UrlParser {
    pub fn new(input_url: Terminal) -> Result<UrlParser, UrlParserErrors> {
        let char_url = input_url.answer;

        if char_url.is_empty() {
            return Err(UrlParserErrors::UrlEmpty);
        }

        if subslice!(char_url, ..7, UrlParserErrors::InvalidSize) != "http://"
            && subslice!(char_url, ..8, UrlParserErrors::InvalidSize) != "https://"
        {
            return Err(UrlParserErrors::InvalidSchemeSintax);
        }

        let scheme = match Sanitize::execute(
            subslice!(char_url, ..4, UrlParserErrors::InvalidSize).to_string(),
            &vec![
                Sanitize::IsType(DesiredType::String),
                Sanitize::MatchString(String::from("http")),
            ],
        ) {
            Ok(_) => Scheme::Http,
            Err(_e) => {
                match Sanitize::execute(
                    subslice!(char_url, ..5, UrlParserErrors::InvalidSize).to_string(),
                    &vec![
                        Sanitize::IsType(DesiredType::String),
                        Sanitize::MatchString(String::from("https")),
                    ],
                ) {
                    Ok(_) => Scheme::Https,
                    Err(_) => return Err(UrlParserErrors::InvalidScheme),
                }
            }
        };

        let target: String = {
            match scheme {
                Scheme::Http => Some(char_url.chars().skip(7).take_while(|c| *c != ':').collect())
                    .ok_or(UrlParserErrors::InvalidSize)?,
                Scheme::Https => Some(char_url.chars().skip(8).take_while(|c| *c != ':').collect())
                    .ok_or(UrlParserErrors::InvalidSize)?,
            }
        };

        let target_type: TargetType = Some(
            TargetType::is_ipv4(&target)
                .or(TargetType::is_ipv6(&target).or(TargetType::is_dns(&target))),
        )
        .ok_or(UrlParserErrors::InvalidTargetType)??;

        let mut port: u16;
        let mut full_url: String;

        Ok(UrlParser {
            scheme,
            target,
            target_type,
            port,
            full_url,
        })
    }
}
