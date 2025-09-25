//use stalkermap::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap::utils::terminal::Terminal;
//use stalkermap::utils::url;
use stalkermap::utils::*;
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

    let banana = Terminal::ask("Between 1-10: ", &[Sanitize::IsBetween(1, 10)]);
    println!("{}", banana.answer);

    let url_input = loop {
        let input = Terminal::ask(
            "Input the target's url: ",
            &[Sanitize::IsType(DesiredType::String)],
        );
        match UrlParser::new(&input.answer) {
            Ok(u) => break u,
            Err(e) => eprintln!("{}", e),
        }
    };

    println!("{}", url_input);
}
