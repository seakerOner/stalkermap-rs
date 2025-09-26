//! # Input Sanitization & Validation
//!
//! This module provides a small yet flexible input validation framework for
//! interactive CLI applications. It defines a set of composable validation
//! filters (`Sanitize`) that can be applied to user-provided strings. Filters
//! run in order and short-circuit on the first failure, returning a friendly
//! error message describing what went wrong.
//!
//! ## Features
//! - Type validation for common Rust primitives via [`DesiredType`]
//! - Exact string matching with [`Sanitize::MatchString`]
//! - Multiple-option matching with [`Sanitize::MatchStrings`]
//! - Inclusive range validation with [`Sanitize::IsBetween`]
//! - Human-readable error messages for invalid input
//!
//! ## When to use
//! Use this module whenever you collect raw user input (e.g. via
//! [`crate::utils::Terminal::ask`]) and need to ensure it matches certain
//! constraints before proceeding.
//!
//! ## Examples
//!
//! ### Validate types
//! ```rust,no_run
//! use stalkermap::utils::{DesiredType, Sanitize, Terminal};
//!
//! let input = Terminal::ask(
//!     "Enter a boolean (true/false):",
//!     &[Sanitize::IsType(DesiredType::Bool)],
//! );
//! println!("Accepted: {}", input.answer);
//! ```
//!
//! ### Match exact strings or options
//! ```rust,no_run
//! use stalkermap::utils::{DesiredType, Sanitize, Terminal};
//!
//! // Exact match
//! let yes = Terminal::ask(
//!     "Type yes to continue:",
//!     &[
//!         Sanitize::IsType(DesiredType::String),
//!         Sanitize::MatchString("yes".to_string()),
//!     ],
//! );
//!
//! // Any of the options
//! let yn = Terminal::ask(
//!     "Continue? (y/n):",
//!     &[
//!         Sanitize::IsType(DesiredType::String),
//!         Sanitize::MatchStrings(vec!["y".to_string(), "n".to_string()]),
//!     ],
//! );
//! println!("{} {}", yes.answer, yn.answer);
//! ```
//!
//! ### Validate numeric range
//! ```rust,no_run
//! use stalkermap::utils::{Sanitize, Terminal};
//!
//! // Ensure input is an integer between 1 and 10 (inclusive)
//! let number = Terminal::ask(
//!     "Enter a number between 1 and 10:",
//!     &[Sanitize::IsBetween(1, 10)],
//! );
//! println!("In range: {}", number.answer);
//! ```
use std::{error::Error, fmt::Display};

/// Represents a validation filter that can be applied to user input.
///
/// - `MatchString`: ensures that the input matches a specific string.
/// - `MatchStrings`: ensures that the input matches one of the given options.
/// - `IsType`: ensures that the input can be parsed into a certain [`DesiredType`].
/// - `IsBetween`: ensures that a numeric input is within an inclusive range `[min, max]`.
pub enum Sanitize {
    MatchString(String),
    MatchStrings(Vec<String>),
    IsType(DesiredType),
    IsBetween(isize, isize),
}

/// Trait for input validation.  
/// Any type that implements this can validate a string input and return
/// either `Ok(())` if the input is valid or a [`FilterErrorNot`] on failure.
trait Validate {
    fn validate(&self, input: &str) -> Result<(), FilterErrorNot>;
}

/// Represents an error that occurs when input validation fails.
///
/// Each variant describes why the input was rejected:
/// - [`Number`]: could not parse as the expected numeric type.
/// - [`String`]: could not parse as string.
/// - [`Bool`]: could not parse as boolean.
/// - [`MatchString`]: did not match the required string.
/// - [`MatchStrings`]: did not match any of the given options.
/// - [`Between`]: did not match between the values given.
#[derive(Debug)]
pub(crate) enum FilterErrorNot {
    Number(DesiredType),
    String(DesiredType),
    Bool(DesiredType),
    MatchString(String),
    MatchStrings(Vec<String>),
    Between(isize, isize),
}

impl Display for FilterErrorNot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(t) => write!(f, "The value is not a {}, try again!", t),
            Self::String(t) => write!(f, "The value is not {}, try again!", t),
            Self::Bool(t) => write!(f, "The value is not a {}, try again!", t),
            Self::MatchString(s) => write!(f, "The value doesn't match with {}, try again!", s),
            Self::MatchStrings(v) => write!(
                f,
                "The value doesn't match with the options: {}, try again!",
                v.join(", ")
            ),
            Self::Between(n1, n2) => {
                write!(f, "The value is not between {} and {}, try again!", n1, n2)
            }
        }
    }
}

impl Error for FilterErrorNot {}

/// Macro helper that validates if an input string can be parsed into the given Rust type.  
/// Expands into a `Result<(), expr>`.
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
/// check_type!(input, u8, Err(FilterErrorNot::Number(DesiredType::U8)));
/// ```
#[macro_export]
macro_rules! check_type {
    ($input:expr, $t:ty, $err:expr) => {
        match $input.parse::<$t>() {
            Ok(_) => Ok(()),
            Err(_) => $err,
        }
    };
}

impl Sanitize {
    /// Executes all provided filters against the given answer.
    ///
    /// - Trims whitespace before validation.
    /// - Stops and returns the first error encountered.
    /// - Returns the cleaned string if all filters pass.
    pub(crate) fn execute(answer: &str, filters: &[Sanitize]) -> Result<String, FilterErrorNot> {
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

impl Validate for Sanitize {
    fn validate(&self, input: &str) -> Result<(), FilterErrorNot> {
        match self {
            Sanitize::IsType(ty) => ty.parse(input),
            Sanitize::MatchString(s) => {
                if input == s {
                    Ok(())
                } else {
                    Err(FilterErrorNot::MatchString(s.to_string()))
                }
            }
            Sanitize::MatchStrings(options) => {
                if options.contains(&input.to_string()) {
                    Ok(())
                } else {
                    Err(FilterErrorNot::MatchStrings(options.clone()))
                }
            }
            Sanitize::IsBetween(n1, n2) => match DesiredType::Isize.parse(input) {
                Ok(_) => {
                    let input_parsed: isize = input.parse().unwrap_or_default();
                    if input_parsed >= *n1 && input_parsed <= *n2 {
                        Ok(())
                    } else {
                        Err(FilterErrorNot::Between(*n1, *n2))
                    }
                }
                Err(e) => Err(e),
            },
        }
    }
}

/// Represents the desired type to which the input should be parsed.
///
/// Used together with [`Sanitize::IsType`] to validate primitive values.
///
/// Currently supports:
/// - `String`
/// - `Bool`
/// - Unsigned integers: `U8`, `U16`, `U32`, `U64`, `U128`
/// - Signed integers: `I8`, `I16`, `I32`, `I64`, `I128`
/// - Platform-sized integer: `Isize`
#[derive(Debug)]
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
    Isize,
}

impl DesiredType {
    /// Matches a [`DesiredType`] variant and applies the corresponding [`check_type!`] validation.
    ///
    /// Expands into a `match` that checks the input string against
    /// all supported [`DesiredType`] variants (string, bool, integers).
    ///
    /// # Example
    /// ```rust,ignore
    /// use stalkermap::utils::DesiredType;
    ///
    /// let input = "true";
    /// let desired = DesiredType::Bool;
    ///
    /// desired.parse(input)? // succeeds if input parses as bool
    /// ```
    fn parse(&self, input: &str) -> Result<(), FilterErrorNot> {
        match self {
            DesiredType::String => {
                check_type!(
                    input,
                    String,
                    Err(FilterErrorNot::String(DesiredType::String))
                )
            }
            DesiredType::Bool => {
                check_type!(input, bool, Err(FilterErrorNot::Bool(DesiredType::Bool)))
            }
            DesiredType::U8 => check_type!(input, u8, Err(FilterErrorNot::Number(DesiredType::U8))),
            DesiredType::U16 => {
                check_type!(input, u16, Err(FilterErrorNot::Number(DesiredType::U16)))
            }
            DesiredType::U32 => {
                check_type!(input, u32, Err(FilterErrorNot::Number(DesiredType::U32)))
            }
            DesiredType::U64 => {
                check_type!(input, u64, Err(FilterErrorNot::Number(DesiredType::U64)))
            }
            DesiredType::U128 => {
                check_type!(input, u128, Err(FilterErrorNot::Number(DesiredType::U128)))
            }
            DesiredType::I8 => check_type!(input, i8, Err(FilterErrorNot::Number(DesiredType::I8))),
            DesiredType::I16 => {
                check_type!(input, i16, Err(FilterErrorNot::Number(DesiredType::I16)))
            }
            DesiredType::I32 => {
                check_type!(input, i32, Err(FilterErrorNot::Number(DesiredType::I32)))
            }
            DesiredType::I64 => {
                check_type!(input, i64, Err(FilterErrorNot::Number(DesiredType::I64)))
            }
            DesiredType::I128 => {
                check_type!(input, i128, Err(FilterErrorNot::Number(DesiredType::I128)))
            }
            DesiredType::Isize => check_type!(
                input,
                isize,
                Err(FilterErrorNot::Number(DesiredType::Isize))
            ),
        }
    }
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
            Self::Isize => write!(f, "isize"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_match_string_sucess() {
        let filter = Sanitize::MatchString("hello".to_string());
        assert!(filter.validate("hello").is_ok());
    }

    #[test]
    fn test_sanitize_match_string_fail() {
        let filter = Sanitize::MatchString("hello".to_string());
        let res = filter.validate("world");
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(
                format!("{}", e),
                "The value doesn't match with hello, try again!"
            );
        }
    }

    #[test]
    fn match_sanitize_match_strings_sucess() {
        let filter = Sanitize::MatchStrings(vec!["A".to_string(), "B".to_string()]);
        assert!(filter.validate("A").is_ok());
        assert!(filter.validate("B").is_ok());
    }

    #[test]
    fn test_sanitize_match_strings_fail() {
        let filter = Sanitize::MatchStrings(vec!["A".to_string(), "B".to_string()]);
        let res = filter.validate("C");
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(
                format!("{}", e),
                "The value doesn't match with the options: A, B, try again!"
            );
        }
    }

    #[test]
    fn test_sanitize_is_type_bool() {
        let filter = Sanitize::IsType(DesiredType::Bool);
        assert!(filter.validate("true").is_ok());
        assert!(filter.validate("false").is_ok());
        assert!(filter.validate("maybe").is_err());
    }

    #[test]
    fn test_sanitize_is_type_u8() {
        let filter = Sanitize::IsType(DesiredType::U8);
        assert!(filter.validate("42").is_ok());
        assert!(filter.validate("-42").is_err());
        assert!(filter.validate("256").is_err()); // u8 max is 255
        assert!(filter.validate("abc").is_err());
    }

    #[test]
    fn test_sanitize_is_type_i32() {
        let filter = Sanitize::IsType(DesiredType::I32);
        assert!(filter.validate("-123").is_ok());
        assert!(filter.validate("2147483647").is_ok()); // i32 max
        assert!(filter.validate("2147483648").is_err()); // overflow
    }

    #[test]
    fn test_sanitize_is_type_isize() {
        let filter = Sanitize::IsBetween(10, 20);
        assert!(filter.validate("15").is_ok());
        assert!(filter.validate("25").is_err()); // Over 20 
        assert!(filter.validate("-20").is_err()); // overflow
    }

    #[test]
    fn test_sanitize_execute_filters_success() {
        let filters = vec![
            Sanitize::IsType(DesiredType::String),
            Sanitize::MatchString("Hello".to_string()),
        ];
        let res = Sanitize::execute("Hello", &filters);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "Hello".to_string());
    }

    #[test]
    fn test_sanitize_execute_filters_fail() {
        let filters = vec![
            Sanitize::MatchString("Hello".to_string()),
            Sanitize::IsType(DesiredType::Bool),
        ];
        let res = Sanitize::execute("Hello", &filters);
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(format!("{}", e), "The value is not a bool, try again!");
        }
    }

    #[test]
    fn test_sanitize_execute_filters_fail2() {
        let filters = vec![
            Sanitize::IsType(DesiredType::Bool),
            Sanitize::IsType(DesiredType::U8),
        ];
        let res = Sanitize::execute("true", &filters);
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(format!("{}", e), "The value is not a u8, try again!");
        }
    }

    #[test]
    fn test_sanitize_execute_filters_fail3() {
        let filters = vec![
            Sanitize::IsType(DesiredType::U8),
            Sanitize::IsType(DesiredType::Bool),
        ];
        let res = Sanitize::execute("true", &filters);
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(format!("{}", e), "The value is not a u8, try again!");
        }
    }

    #[test]
    fn test_sanitize_execute_filters_fail4() {
        let filters = vec![
            Sanitize::IsType(DesiredType::String),
            Sanitize::MatchStrings(vec![String::from("banana"), String::from("orange")]),
        ];
        let res = Sanitize::execute("watermelon", &filters);
        assert!(res.is_err());
        if let Err(e) = res {
            assert_eq!(
                format!("{}", e),
                "The value doesn't match with the options: banana, orange, try again!"
            );
        }
    }
}
