//use stalkermap::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap::utils::terminal::Terminal;
//use stalkermap::utils::url;
//use stalkermap::dns::resolver::{resolve_cname, resolve_ipv4, resolve_ipv4_async, resolve_txt};
//use stalkermap::utils::*;
use stalkermap::dns::resolver::{resolve_ipv4_async, resolve_txt_async};
use tokio::join;

#[tokio::main]
async fn main() {
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

    let (r1, r2) = join!(
        resolve_ipv4_async("crescemais.pt"),
        resolve_txt_async("crescemais.pt")
    );

    match r1 {
        Ok(ips) => println!("{:#?}", ips),
        Err(e) => eprintln!("{}", e),
    }
    match r2 {
        Ok(ips) => println!("{:#?}", ips),
        Err(e) => eprintln!("{}", e),
    }

    //match resolve_ipv4("example.com") {
    //    Ok(ips) => println!("{:#?}", ips),
    //    Err(e) => eprintln!("{}", e),
    //}

    //let url_input = loop {
    //    let input = Terminal::ask(
    //        "Input the target's url: ",
    //        &[Sanitize::IsType(DesiredType::String)],
    //    );
    //    match UrlParser::new(&input.answer) {
    //        Ok(u) => break u,
    //        Err(e) => eprintln!("{}", e),
    //    }
    //};

    //println!("{}", url_input);
}
