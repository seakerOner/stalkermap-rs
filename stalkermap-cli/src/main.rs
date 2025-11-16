use std::str::FromStr;

//use stalkermap::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap::utils::terminal::Terminal;
//use stalkermap::utils::url;
//use stalkermap::dns::resolver::{resolve_cname, resolve_ipv4, resolve_ipv4_async, resolve_txt};
//use stalkermap::utils::*;
//use stalkermap::dns::resolver::{resolve_ipv4_async, resolve_txt_async};
use stalkermap::scanner::*;
use stalkermap::utils::*;

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

    let scanner = Scanner::<RawFormatter>::new().build();
    let mut logs = scanner.get_logs_stream().await.unwrap();

    scanner.add_multiple_tasks(vec![
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
    ]);

    let l = vec![
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
        Task::new(
            vec![Actions::PortIsOpen],
            UrlParser::from_str("https://127.0.0.1:80").unwrap(),
        ),
    ];

    tokio::spawn(async move {
        loop {
            match logs.next().await {
                Some(log) => {
                    if RawFormatter.is_idle_signal(&log) {
                        logs.notify_when_new_tasks().await;
                    } else {
                        println!("Log: {:#?}", log);
                    }
                }
                None => {
                    break;
                }
            }
        }
    });
    scanner.execute_tasks();

    scanner.await_idle().await;

    scanner.add_multiple_tasks(l);

    scanner.shutdown_graceful().await;
}
