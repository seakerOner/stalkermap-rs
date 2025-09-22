use crate::utils::sanitize::Sanitize;
use std::io;

/// A helper for repeatedly asking the user for input until it passes all [`Sanitize`] filters.  
/// Internally calls [`Sanitize::execute`].
///
/// # Examples
///
/// ## Example 1: Boolean input
/// ```rust,no_run
/// use stalkermap_core::utils::{DesiredType, Sanitize, Terminal};
///
///
/// let input = Terminal::ask(
///     "You like Rust? (true/false)",
///     vec![Sanitize::IsType(DesiredType::Bool)],
/// );
///
/// println!("The input: {}", input.answer);
/// ```
///
/// ## Example 2: Restricted string input
/// ```rust,no_run
/// use stalkermap_core::utils::{DesiredType, Sanitize, Terminal};
///
/// let input2 = Terminal::ask(
///     "You like Rust? Y/N",
///     vec![
///         Sanitize::IsType(DesiredType::String),
///         Sanitize::MatchStrings(vec![
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
    pub fn ask(question: &str, filters: Vec<Sanitize>) -> Terminal {
        let answer: String = loop {
            println!("{}", question);
            let mut answer = String::new();

            match io::stdin().read_line(&mut answer) {
                Ok(_) => {
                    let sanatized_answer = Sanitize::execute(answer, &filters);

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
