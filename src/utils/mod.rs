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

/// Represents an error that occurs when input validation fails.
///
/// Each variant describes a specific reason why the input was rejected:
/// - Not a valid number, string, or boolean.
/// - Did not match a required single string.
/// - Did not match any of a set of allowed strings.
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

/// Validates that an input string can be parsed into the given type.
///
/// If parsing succeeds, the loop continues.  
/// If parsing fails, the provided error expression is returned.
///
/// # Parameters
/// - `$input`: The input string to parse (usually trimmed user input).
/// - `$t`: The Rust type to parse into (e.g. `u8`, `i32`, `bool`).
/// - `$err`: The error expression to return when parsing fails.
///
/// # Example
/// ```rust,ignore
/// let input = String::from("42");
/// check_type!(
///     input,
///     u8,
///     Err(FilterErrorMessage::NotNumber(DesiredType::U8))
/// );
/// ```
#[macro_export]
macro_rules! check_type {
    ($input:expr, $t:ty, $err:expr) => {
        match $input.parse::<$t>() {
            Ok(_) => continue,
            Err(_) => return $err,
        }
    };
}

/// Matches a [`DesiredType`] variant and applies the corresponding [`check_type!`] validation.
///
/// This macro expands into a `match` block that checks the input against
/// all supported [`DesiredType`] variants (`String`, `Bool`, integers).
///
/// # Parameters
/// - `$input`: The input string to validate.
/// - `$sanatize`: A [`DesiredType`] enum variant.
///
/// # Example
/// ```rust,ignore
/// let input = String::from("true");
/// let desired = DesiredType::Bool;
///
/// match_sanatize!(
///     input,
///     desired
/// ); // succeeds if input parses as bool, otherwise returns an error
/// ```
#[macro_export]
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
    fn execute(answer: String, filters: &Vec<Sanatize>) -> Result<String, FilterErrorMessage> {
        let clean_answer = answer.trim();

        for filter in filters {
            match filter {
                Sanatize::IsType(t) => match_sanatize!(clean_answer, t),
                Sanatize::MatchString(s) => {
                    if clean_answer == s {
                        continue;
                    } else {
                        return Err(FilterErrorMessage::NotMatchString(s.to_string()));
                    }
                }
                Sanatize::MatchStrings(vector) => {
                    if vector.contains(&clean_answer.to_string()) {
                        continue;
                    } else {
                        return Err(FilterErrorMessage::NotMatchStrings());
                    }
                }
            };
        }
        Ok(clean_answer.to_string())
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
///
/// # Examples
///
/// ## Example 1: Boolean input
/// ```rust,no_run
/// use stalkermap_core::{Terminal, Sanatize, DesiredType};
///
/// let url_input = Terminal::ask(
///     "You like Rust? (true/false)",
///     vec![Sanatize::IsType(DesiredType::Bool)],
/// );
///
/// println!("The input: {}", url_input.answer);
/// ```
///
/// ## Example 2: Restricted string input
/// ```rust,no_run
/// use stalkermap_core::{Terminal, Sanatize, DesiredType};
///
/// let url_input2 = Terminal::ask(
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
/// println!("The input: {}", url_input2.answer);
/// ```
pub struct Terminal {
    pub answer: String,
}

impl Terminal {
    /// Print a question to the terminal and loops it until it gets the desired answer with
    ///  
    ///  # Example 1
    ///
    ///  ```
    ///  let url_input = Terminal::ask("You like Rust? (true/ false) ", vec![Sanatize::IsType(DesiredType::Bool)],);
    ///
    ///  println!("The input: {}", url_input.answer);
    ///  ```
    ///  
    ///  # Example 2
    ///
    ///  ```
    ///   let url_input2 = Terminal::ask(
    ///    "You like Rust? Y/N ",
    ///    vec![
    ///        Sanatize::IsType(DesiredType::String),
    ///        Sanatize::MatchStrings(vec![
    ///            String::from("Y"),
    ///            String::from("N"),
    ///            String::from("y"),
    ///            String::from("n"),
    ///        ]),
    ///      ],
    ///   );
    ///
    ///   println!("The input: {}", url_input2.answer);
    ///  ```

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
