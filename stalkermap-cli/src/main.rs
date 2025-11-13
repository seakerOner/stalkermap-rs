use std::str::FromStr;

//use stalkermap::utils::sanitize::{DesiredType, Sanitize};
//use stalkermap::utils::terminal::Terminal;
//use stalkermap::utils::url;
//use stalkermap::dns::resolver::{resolve_cname, resolve_ipv4, resolve_ipv4_async, resolve_txt};
//use stalkermap::utils::*;
use stalkermap::dns::resolver::{resolve_ipv4_async, resolve_txt_async};
use stalkermap::scanner::*;
use stalkermap::utils::*;
use tokio::io::join;
use tokio::join;
use tokio_stream::StreamExt;

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

    //let r1 = resolve_ipv4_async("crescemais.pt").await.unwrap();

    let scanner = Scanner::<StructuredFormatter>::new().build();
    let mut logs = scanner.get_logs_stream().await.unwrap();

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

    scanner.add_multiple_tasks(l);

    let ll = vec![
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

    let logger = tokio::spawn(async move {
        while let Ok(Some(log)) = logs.try_next().await {
            println!("Log: {:#?}", log);
        }
    });

    // let scanner_clone = scanner.clone();
    // let await_idle = tokio::spawn(async move {
    //     scanner_clone.await_idle().await;
    // });

    // let _ = join!(logger, await_idle);
    scanner.add_multiple_tasks(ll);
    println!("finished adding tasks");

    let scanner_clone2 = scanner.clone();
    let shutdown_task = tokio::task::spawn(async move {
        scanner_clone2.shutdown_graceful().await;
    });
    scanner.execute_tasks();

    let _ = join!(logger, shutdown_task);
    //logger.await.unwrap();
}
