//! Узел без TUN с TCP-консолью управления через yggdrasil.
//!
//! Консоль — обычный [`YggTcpListener`] внутри overlay. К нему можно
//! подключиться с другого узла по адресу `[address]:control_port` и
//! отправлять текстовые команды, например `peer tcp://host:7992`.
//!
//! Запуск:
//!
//! ```text
//! uu-yggdrasil-control
//! uu-yggdrasil-control --config ./yggdrasil.toml --control-port 4456
//! ```
//!
//! Внимание: у консоли нет аутентификации. Не выставляйте её в недоверенной
//! сети: любой узел, который может до неё достучаться, сможет добавлять пиров.

#[path = "common/mod.rs"]
mod common;

use clap::Parser;
use std::{error::Error, sync::Arc};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use uu_yggdrasil::{
    YggTcpListener, YggTcpStream, Yggdrasil,
    cli::ArgsYgg,
    config::{self, LoadedConfig},
};

const MAX_COMMAND_LEN: usize = 4096;
const WELCOME: &str = "uu-yggdrasil control. Type 'help' for commands.\n";
const HELP: &str = "\
commands:
  status          адрес, публичный ключ и число подключённых пиров
  peers           публичные ключи подключённых пиров
  peer <uri>      подключиться к пиру, например tcp://host:7992
  help            эта справка
  quit            закрыть консоль
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    uu_yggdrasil::init_tracing();
    let args = ArgsYgg::parse();
    if args.generate.run()? {
        return Ok(());
    }

    let LoadedConfig {
        yggdrasil,
        peers,
        listen,
        remote_control,
    } = match args.config {
        Some(path) => config::load_config(&path, false, false)?,
        None => todo!("BUG"),
    };

    let node = Arc::new(Yggdrasil::new(yggdrasil).await?);
    println!("yggdrasil control node (TUN disabled)");
    println!("public key: {}", config::hex(node.public_key().as_bytes()));
    println!("address: {}", node.address());
    for address in listen {
        let bound = node.listen_tcp(address).await?;
        println!("peer listener: tcp://{bound}");
    }

    let mut peer_tasks = Vec::with_capacity(peers.len());
    for uri in peers {
        let node = Arc::clone(&node);
        peer_tasks.push(tokio::spawn(async move {
            common::maintain_peer(node, uri).await;
        }));
    }

    let control_task = if remote_control.enabled {
        let listener = node.tcp_listen(remote_control.port).await?;
        println!(
            "control: [{}]:{} (TCP)",
            node.address(),
            listener.local_addr().port()
        );
        Some(tokio::spawn(control_accept_loop(
            Arc::clone(&node),
            listener,
        )))
    } else {
        println!("control: disabled");
        None
    };

    println!("running; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    println!("shutting down");
    if let Some(task) = control_task {
        task.abort();
    }
    for task in peer_tasks {
        task.abort();
    }
    node.close();
    Ok(())
}

async fn control_accept_loop(node: Arc<Yggdrasil>, mut listener: YggTcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                println!("control: {peer} connected");
                tokio::spawn(control_session(Arc::clone(&node), stream));
            }
            Err(error) => {
                eprintln!("control listener stopped: {error}");
                break;
            }
        }
    }
}

async fn control_session(node: Arc<Yggdrasil>, stream: YggTcpStream) {
    let peer = stream.peer_addr();
    let mut reader = BufReader::new(stream);
    if reader
        .get_mut()
        .write_all(WELCOME.as_bytes())
        .await
        .is_err()
    {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) if line.len() > MAX_COMMAND_LEN => {
                let _ = reader
                    .get_mut()
                    .write_all(b"error: command is too long\n")
                    .await;
                break;
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("control {peer}: read: {error}");
                break;
            }
        }

        let (reply, quit) = execute_command(&node, line.trim()).await;
        if reader.get_mut().write_all(reply.as_bytes()).await.is_err() {
            break;
        }
        if quit {
            break;
        }
    }

    let _ = reader.get_mut().shutdown().await;
    println!("control: {peer} closed");
}

async fn execute_command(node: &Yggdrasil, line: &str) -> (String, bool) {
    match parse_command(line) {
        Command::Help | Command::Empty => (HELP.to_owned(), false),
        Command::Status => (
            format!(
                "address: {}\npublic_key: {}\npeers: {}\n",
                node.address(),
                config::hex(node.public_key().as_bytes()),
                node.node().peer_count()
            ),
            false,
        ),
        Command::Peers => {
            let keys = node.node().peer_keys();
            if keys.is_empty() {
                ("peers: none\n".to_owned(), false)
            } else {
                let mut reply = String::new();
                for key in keys {
                    reply.push_str(&config::hex(key.as_bytes()));
                    reply.push('\n');
                }
                (reply, false)
            }
        }
        Command::Peer("") => ("error: usage: peer <uri>\n".to_owned(), false),
        Command::Peer(uri) => match node.peer_uri(uri).await {
            Ok(info) => (
                format!(
                    "connected: {} {} (priority {})\n",
                    config::hex(info.key.as_bytes()),
                    info.address,
                    info.priority
                ),
                false,
            ),
            Err(error) => (format!("error: {error}\n"), false),
        },
        Command::Quit => ("bye\n".to_owned(), true),
        Command::Unknown(command) => (format!("error: unknown command: {command}\n{HELP}"), false),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Empty,
    Help,
    Status,
    Peers,
    Peer(&'a str),
    Quit,
    Unknown(&'a str),
}

fn parse_command(line: &str) -> Command<'_> {
    if line.is_empty() {
        return Command::Empty;
    }
    let (command, argument) = line
        .split_once(char::is_whitespace)
        .map_or((line, ""), |(command, argument)| (command, argument.trim()));
    match command.to_ascii_lowercase().as_str() {
        "help" | "?" => Command::Help,
        "status" => Command::Status,
        "peers" => Command::Peers,
        "peer" | "connect" => Command::Peer(argument),
        "quit" | "exit" => Command::Quit,
        _ => Command::Unknown(line),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicU16, Ordering},
        },
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        time::{Duration, timeout},
    };
    use uu_yggdrasil::{Yggdrasil, YggdrasilConfig, config};

    use crate::{Command, control_accept_loop, parse_command};

    fn control_port() -> u16 {
        static NEXT: AtomicU16 = AtomicU16::new(24_000);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn parses_control_commands() {
        assert_eq!(parse_command(""), Command::Empty);
        assert_eq!(parse_command("status"), Command::Status);
        assert_eq!(parse_command("PEERS"), Command::Peers);
        assert_eq!(
            parse_command("peer tcp://example.com:7992"),
            Command::Peer("tcp://example.com:7992")
        );
        assert_eq!(parse_command("quit"), Command::Quit);
        assert_eq!(parse_command("wat"), Command::Unknown("wat"));
    }

    #[tokio::test]
    async fn control_shell_answers_over_overlay() {
        let a = Arc::new(Yggdrasil::new(YggdrasilConfig::default()).await.unwrap());
        let b = Arc::new(Yggdrasil::new(YggdrasilConfig::default()).await.unwrap());
        let peer_addr = a
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        b.peer_tcp(peer_addr.ip(), peer_addr.port()).await.unwrap();

        let port = control_port();
        let listener = a.tcp_listen(port).await.unwrap();
        let task = tokio::spawn(control_accept_loop(Arc::clone(&a), listener));

        let stream = timeout(Duration::from_secs(5), b.tcp_connect(a.address(), port))
            .await
            .unwrap()
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("control"));

        reader.get_mut().write_all(b"status\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("address:"));
        for _ in 0..2 {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
        }

        reader.get_mut().write_all(b"peers\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim(), config::hex(b.public_key().as_bytes()));
        task.abort();
        a.close();
        b.close();
    }
}
