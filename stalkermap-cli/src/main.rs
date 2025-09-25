//use stalkermap_core::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap_core::utils::terminal::Terminal;
//use stalkermap_core::utils::url;
use stalkermap_core::utils::*;
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
