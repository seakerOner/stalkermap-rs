//use stalkermap::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap::utils::terminal::Terminal;
//use stalkermap::utils::url;
use stalkermap::dns::resolver::{resolve_cname, resolve_ipv4, resolve_txt};
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
    match resolve_ipv4("example.com") {
        Ok(ips) => println!("{:#?}", ips),
        Err(e) => eprintln!("{}", e),
    }
    match resolve_cname("example.com") {
        Ok(v) => println!("{:#?}", v),
        Err(e) => eprintln!("{}", e),
    }
    match resolve_txt("example.com") {
        Ok(v) => println!("{:#?}", v),
        Err(e) => eprintln!("{}", e),
    }

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
