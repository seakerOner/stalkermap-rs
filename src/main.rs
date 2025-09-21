use stalkermap_rs::utils::{DesiredType, Sanatize, Terminal};

fn main() {
    println!(
        "------------------------------------------------------------------------------------",
    );
    println!(
        "███████ ████████  █████  ██      ██   ██ ███████ ██████  ███    ███  █████  ██████  ",
    );
    println!(
        "██         ██    ██   ██ ██      ██  ██  ██      ██   ██ ████  ████ ██   ██ ██   ██ ",
    );
    println!(
        "███████    ██    ███████ ██      █████   █████   ██████  ██ ████ ██ ███████ ██████  ",
    );
    println!(
        "     ██    ██    ██   ██ ██      ██  ██  ██      ██   ██ ██  ██  ██ ██   ██ ██      ",
    );
    println!(
        "███████    ██    ██   ██ ███████ ██   ██ ███████ ██   ██ ██      ██ ██   ██ ██      ",
    );
    println!(
        "                         CREATED BY:            SEAK                                ",
    );
    println!(
        "                            VERSION:            0.0.1                               ",
    );
    println!(
        "------------------------------------------------------------------------------------",
    );

    let url_input = Terminal::ask(
        "You like Rust? (true/ false) ",
        vec![Sanatize::IsType(DesiredType::Bool)],
    );

    println!("The input: {}", url_input.answer);

    let url_input2 = Terminal::ask(
        "You like Rust? Y/N ",
        vec![
            Sanatize::IsType(DesiredType::String),
            Sanatize::MatchStrings(vec![
                String::from("Y"),
                String::from("N"),
                String::from("y"),
                String::from("n"),
            ]),
        ],
    );

    println!("The input: {}", url_input2.answer);
}
