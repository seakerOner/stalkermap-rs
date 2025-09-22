use std::{fmt::Display, io};

/// Represents a validation filter that can be applied to user input.
///
/// - `MatchString`: ensures that the input matches a specific string.
/// - `MatchStrings`: ensures that the input matches one of the given options.
/// - `IsType`: ensures that the input can be parsed into a certain [`DesiredType`].
pub enum Sanatize {
    MatchString(String),
    MatchStrings(Vec<String>),
    IsType(DesiredType),
}

/// Trait for input validation.  
/// Any type that implements this can validate a string input and return
/// either `Ok(())` if the input is valid or a [`FilterErrorMessage`] on failure.
trait Validate {
    fn validate(&self, input: &str) -> Result<(), FilterErrorMessage>;
}

/// Represents an error that occurs when input validation fails.
///
/// Each variant describes why the input was rejected:
/// - [`NotNumber`]: could not parse as the expected numeric type.
/// - [`NotString`]: could not parse as string.
/// - [`NotBool`]: could not parse as boolean.
/// - [`NotMatchString`]: did not match the required string.
/// - [`NotMatchStrings`]: did not match any of the given options.
enum FilterErrorMessage {
    NotNumber(DesiredType),
    NotString(DesiredType),
    NotBool(DesiredType),
    NotMatchString(String),
    NotMatchStrings(),
}

impl Display for FilterErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotNumber(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotString(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotBool(t) => {
                write!(f, "The value is not a {}, try again!", t)
            }
            Self::NotMatchString(s) => {
                write!(f, "The value doesn't match with {}, try again!", s)
            }
            Self::NotMatchStrings() => {
                write!(f, "The value doesn't match with the options, try again!",)
            }
        }
    }
}

/// Macro helper that validates if an input string can be parsed into the given Rust type.  
/// Expands into a `Result<(), FilterErrorMessage>`.
///
/// # Parameters
/// - `$input`: The input string to parse.
/// - `$t`: The Rust type (e.g. `u8`, `i32`, `bool`).
/// - `$err`: The error to return if parsing fails.
///
/// # Example
/// ```rust,ignore
///
/// let input = "42";
/// check_type!(input, u8, Err(FilterErrorMessage::NotNumber(DesiredType::U8)));
/// ```

/// #[doc(hidden)]
macro_rules! check_type {
    ($input:expr, $t:ty, $err:expr) => {
        match $input.parse::<$t>() {
            Ok(_) => Ok(()),
            Err(_) => return $err,
        }
    };
}

/// Matches a [`DesiredType`] variant and applies the corresponding [`check_type!`] validation.
///
/// Expands into a `match` that checks the input string against
/// all supported [`DesiredType`] variants (string, bool, integers).
///
/// # Example
/// ```rust,ignore
/// use stalkermap_core::utils::DesiredType;
///
/// let input = "true";
/// let desired = DesiredType::Bool;
///
/// match_sanatize!(input, desired)?; // succeeds if input parses as bool
/// ```

/// #[doc(hidden)]
macro_rules! match_sanatize {
    ( $input:expr, $sanatize:expr ) => {
        match $sanatize {
            DesiredType::String => check_type!(
                $input,
                String,
                Err(FilterErrorMessage::NotString(DesiredType::String))
            ),
            DesiredType::Bool => check_type!(
                $input,
                bool,
                Err(FilterErrorMessage::NotBool(DesiredType::Bool))
            ),
            DesiredType::U8 => check_type!(
                $input,
                u8,
                Err(FilterErrorMessage::NotNumber(DesiredType::U8))
            ),
            DesiredType::U16 => check_type!(
                $input,
                u16,
                Err(FilterErrorMessage::NotNumber(DesiredType::U16))
            ),
            DesiredType::U32 => check_type!(
                $input,
                u32,
                Err(FilterErrorMessage::NotNumber(DesiredType::U32))
            ),
            DesiredType::U64 => check_type!(
                $input,
                u64,
                Err(FilterErrorMessage::NotNumber(DesiredType::U64))
            ),
            DesiredType::U128 => check_type!(
                $input,
                u128,
                Err(FilterErrorMessage::NotNumber(DesiredType::U128))
            ),
            DesiredType::I8 => check_type!(
                $input,
                i8,
                Err(FilterErrorMessage::NotNumber(DesiredType::I8))
            ),
            DesiredType::I16 => check_type!(
                $input,
                i16,
                Err(FilterErrorMessage::NotNumber(DesiredType::I16))
            ),
            DesiredType::I32 => check_type!(
                $input,
                i32,
                Err(FilterErrorMessage::NotNumber(DesiredType::I32))
            ),
            DesiredType::I64 => check_type!(
                $input,
                i64,
                Err(FilterErrorMessage::NotNumber(DesiredType::I64))
            ),
            DesiredType::I128 => check_type!(
                $input,
                i128,
                Err(FilterErrorMessage::NotNumber(DesiredType::I128))
            ),
        }
    };
}
impl Sanatize {
    /// Executes all provided filters against the given answer.
    ///
    /// - Trims whitespace before validation.
    /// - Stops and returns the first error encountered.
    /// - Returns the cleaned string if all filters pass.
    fn execute(answer: String, filters: &Vec<Sanatize>) -> Result<String, FilterErrorMessage> {
        let clean_answer = answer.trim();

        for filter in filters {
            match filter.validate(clean_answer) {
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(clean_answer.to_string())
    }
}

impl Validate for Sanatize {
    fn validate(&self, input: &str) -> Result<(), FilterErrorMessage> {
        match self {
            Sanatize::IsType(t) => match_sanatize!(input, t),
            Sanatize::MatchString(s) => {
                if input == s {
                    Ok(())
                } else {
                    Err(FilterErrorMessage::NotMatchString(s.to_string()))
                }
            }
            Sanatize::MatchStrings(options) => {
                if options.contains(&input.to_string()) {
                    Ok(())
                } else {
                    Err(FilterErrorMessage::NotMatchStrings())
                }
            }
        }
    }
}

/// Represents the desired type to which the input should be parsed.
///
/// Used together with [`Sanatize::IsType`] to validate primitive values.
///
/// Currently supports:
/// - `String`
/// - `Bool`
/// - Unsigned integers: `U8`, `U16`, `U32`, `U64`, `U128`
/// - Signed integers: `I8`, `I16`, `I32`, `I64`, `I128`
pub enum DesiredType {
    String,
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,
}

impl Display for DesiredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::U128 => write!(f, "u128"),
            Self::I8 => write!(f, "i8"),
            Self::I16 => write!(f, "i16"),
            Self::I32 => write!(f, "i32"),
            Self::I64 => write!(f, "i64"),
            Self::I128 => write!(f, "i128"),
        }
    }
}

/// A helper for repeatedly asking the user for input until it passes all [`Sanatize`] filters.  
/// Internally calls [`Sanatize::execute`].
///
/// # Examples
///
/// ## Example 1: Boolean input
/// ```rust,no_run
/// use stalkermap_core::utils::{DesiredType, Sanatize, Terminal};
///
///
/// let input = Terminal::ask(
///     "You like Rust? (true/false)",
///     vec![Sanatize::IsType(DesiredType::Bool)],
/// );
///
/// println!("The input: {}", input.answer);
/// ```
///
/// ## Example 2: Restricted string input
/// ```rust,no_run
/// use stalkermap_core::utils::{DesiredType, Sanatize, Terminal};
///
/// let input2 = Terminal::ask(
///     "You like Rust? Y/N",
///     vec![
///         Sanatize::IsType(DesiredType::String),
///         Sanatize::MatchStrings(vec![
///             String::from("Y"),
///             String::from("N"),
///             String::from("y"),
///             String::from("n"),
///         ]),
///     ],
/// );
///
/// println!("The input: {}", input2.answer);
/// ```
pub struct Terminal {
    pub answer: String,
}

impl Terminal {
    /// Prints a question to the terminal and loops until a valid answer is received.  
    /// Returns a [`Terminal`] struct containing the accepted answer.
    pub fn ask(question: &str, filters: Vec<Sanatize>) -> Terminal {
        let answer: String = loop {
            println!("{}", question);
            let mut answer = String::new();

            match io::stdin().read_line(&mut answer) {
                Ok(_) => {
                    let sanatized_answer = Sanatize::execute(answer, &filters);

                    match sanatized_answer {
                        Ok(data) => break data,
                        Err(e) => {
                            println!("{}", e);
                            continue;
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Couldn't read line..");
                    continue;
                }
            };
        };

        Terminal { answer: answer }
    }
}

pub struct UrlCompose {
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

enum TargetType {
    Dns,
    IPv4,
    IPv6,
}

enum UrlComposeErrors {
    UrlEmpty,
    InvalidSize,
    InvalidScheme,
    InvalidSchemeSintax,
    InvalidPort,
}

impl Display for UrlComposeErrors {
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
            Self::InvalidSchemeSintax => {
                write!(f, "Invalid scheme sintax => http:// or https://")
            }
            Self::InvalidPort => {
                write!(f, "Invalid port => (1 -> 65,535)")
            }
        }
    }
}

impl UrlCompose {
    pub fn new(input_url: Terminal) -> Result<UrlCompose, UrlComposeErrors> {
        let char_url = input_url.answer;
        let mut target: String = String::new();
        let mut target_type: TargetType;
        let mut port: u16;
        let mut full_url: String;

        if char_url.is_empty() {
            return Err(UrlComposeErrors::UrlEmpty);
        }

        if char_url.get(..7).ok_or(UrlComposeErrors::InvalidSize)? != "http://"
            && char_url.get(..8).ok_or(UrlComposeErrors::InvalidSize)? != "https://"
        {
            return Err(UrlComposeErrors::InvalidSchemeSintax);
        }

        let scheme = match Sanatize::execute(
            char_url
                .get(..4)
                .ok_or(UrlComposeErrors::InvalidSize)?
                .to_string(),
            &vec![
                Sanatize::IsType(DesiredType::String),
                Sanatize::MatchString(String::from("http")),
            ],
        ) {
            Ok(_) => Scheme::Http,
            Err(_e) => {
                match Sanatize::execute(
                    char_url
                        .get(..5)
                        .ok_or(UrlComposeErrors::InvalidSize)?
                        .to_string(),
                    &vec![
                        Sanatize::IsType(DesiredType::String),
                        Sanatize::MatchString(String::from("https")),
                    ],
                ) {
                    Ok(_) => Scheme::Https,
                    Err(_) => return Err(UrlComposeErrors::InvalidScheme),
                }
            }
        };

        Ok(UrlCompose {
            scheme,
            target,
            target_type,
            port,
            full_url,
        })
    }
}
