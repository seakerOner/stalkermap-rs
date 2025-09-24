use std::fmt::Display;

/// Represents a validation filter that can be applied to user input.
///
/// - `MatchString`: ensures that the input matches a specific string.
/// - `MatchStrings`: ensures that the input matches one of the given options.
/// - `IsType`: ensures that the input can be parsed into a certain [`DesiredType`].
pub enum Sanitize {
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
#[derive(Debug)]
pub(crate) enum FilterErrorMessage {
    NotNumber(DesiredType),
    NotString(DesiredType),
    NotBool(DesiredType),
    NotMatchString(String),
    NotMatchStrings(Vec<String>),
}

impl Display for FilterErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotNumber(t) => write!(f, "The value is not a {}, try again!", t),
            Self::NotString(t) => write!(f, "The value is not {}, try again!", t),
            Self::NotBool(t) => write!(f, "The value is not a {}, try again!", t),
            Self::NotMatchString(s) => write!(f, "The value doesn't match with {}, try again!", s),
            Self::NotMatchStrings(v) => write!(
                f,
                "The value doesn't match with the options: {}, try again!",
                v.join(", ")
            ),
        }
    }
}

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
/// check_type!(input, u8, Err(FilterErrorMessage::NotNumber(DesiredType::U8)));
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
    pub(crate) fn execute(
        answer: &str,
        filters: &[Sanitize],
    ) -> Result<String, FilterErrorMessage> {
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
    fn validate(&self, input: &str) -> Result<(), FilterErrorMessage> {
        match self {
            Sanitize::IsType(ty) => ty.parse(input),
            Sanitize::MatchString(s) => {
                if input == s {
                    Ok(())
                } else {
                    Err(FilterErrorMessage::NotMatchString(s.to_string()))
                }
            }
            Sanitize::MatchStrings(options) => {
                if options.contains(&input.to_string()) {
                    Ok(())
                } else {
                    Err(FilterErrorMessage::NotMatchStrings(options.clone()))
                }
            }
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
}

impl DesiredType {
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
    /// desired.parse(input)? // succeeds if input parses as bool
    /// ```

    fn parse(&self, input: &str) -> Result<(), FilterErrorMessage> {
        match self {
            DesiredType::String => {
                check_type!(
                    input,
                    String,
                    Err(FilterErrorMessage::NotString(DesiredType::String))
                )
            }
            DesiredType::Bool => check_type!(
                input,
                bool,
                Err(FilterErrorMessage::NotBool(DesiredType::Bool))
            ),
            DesiredType::U8 => check_type!(
                input,
                u8,
                Err(FilterErrorMessage::NotNumber(DesiredType::U8))
            ),
            DesiredType::U16 => check_type!(
                input,
                u16,
                Err(FilterErrorMessage::NotNumber(DesiredType::U16))
            ),
            DesiredType::U32 => check_type!(
                input,
                u32,
                Err(FilterErrorMessage::NotNumber(DesiredType::U32))
            ),
            DesiredType::U64 => check_type!(
                input,
                u64,
                Err(FilterErrorMessage::NotNumber(DesiredType::U64))
            ),
            DesiredType::U128 => check_type!(
                input,
                u128,
                Err(FilterErrorMessage::NotNumber(DesiredType::U128))
            ),
            DesiredType::I8 => check_type!(
                input,
                i8,
                Err(FilterErrorMessage::NotNumber(DesiredType::I8))
            ),
            DesiredType::I16 => check_type!(
                input,
                i16,
                Err(FilterErrorMessage::NotNumber(DesiredType::I16))
            ),
            DesiredType::I32 => check_type!(
                input,
                i32,
                Err(FilterErrorMessage::NotNumber(DesiredType::I32))
            ),
            DesiredType::I64 => check_type!(
                input,
                i64,
                Err(FilterErrorMessage::NotNumber(DesiredType::I64))
            ),
            DesiredType::I128 => check_type!(
                input,
                i128,
                Err(FilterErrorMessage::NotNumber(DesiredType::I128))
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
