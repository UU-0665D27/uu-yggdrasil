//! Узел без TUN с TCP- и UDP-echo серверами на порту 4455.
//!
//! Порты существуют только внутри yggdrasil: ОС их не занимает.
//! Опциональный конфиг задаёт ключ, пиров и listen-адреса; TUN из конфига
//! всегда игнорируется.
//!
//! Запуск:
//!
//! ```text
//! uu-yggdrasil-echo
//! uu-yggdrasil-echo --config ./yggdrasil.json
//! ```

#[path = "common/mod.rs"]
mod common;

use std::{env, error::Error, io, path::PathBuf, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uu_yggdrasil::{YggTcpListener, YggTcpStream, YggUdpSocket, Yggdrasil, YggdrasilConfig};

const ECHO_PORT: u16 = 4455;
const TCP_BUFFER: usize = 16 * 1024;
const UDP_BUFFER: usize = 65_535;

const HELP: &str = "\
Usage: uu-yggdrasil-echo [--config <path>]

  --config <path>  JSON-конфиг (ключ, пиры, listen); TUN игнорируется
  -h, --help       показать эту справку";

struct Args {
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    let common::LoadedConfig {
        yggdrasil,
        peers,
        listen,
    } = match args.config {
        Some(path) => common::load_config(&path, false, false)?,
        None => common::LoadedConfig {
            yggdrasil: YggdrasilConfig::default(),
            peers: Vec::new(),
            listen: Vec::new(),
        },
    };

    let node = Arc::new(Yggdrasil::new(yggdrasil).await?);
    println!("yggdrasil echo node (TUN disabled)");
    println!("public key: {}", common::hex(node.public_key().as_bytes()));
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

    let tcp = node.tcp_listen(ECHO_PORT).await?;
    let udp = node.udp_bind(ECHO_PORT).await?;
    println!("echo: [{}]:{ECHO_PORT} (TCP+UDP)", node.address());
    println!("running; press Ctrl-C to stop");

    let tcp_task = tokio::spawn(tcp_accept_loop(tcp));
    let udp_task = tokio::spawn(async move {
        if let Err(error) = udp_echo_loop(udp).await {
            eprintln!("udp echo stopped: {error}");
        }
    });

    tokio::signal::ctrl_c().await?;
    println!("shutting down");
    tcp_task.abort();
    udp_task.abort();
    for task in peer_tasks {
        task.abort();
    }
    node.close();
    Ok(())
}

async fn tcp_accept_loop(mut listener: YggTcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(echo_tcp(stream));
            }
            Err(error) => {
                eprintln!("tcp echo listener stopped: {error}");
                break;
            }
        }
    }
}

async fn echo_tcp(mut stream: YggTcpStream) {
    let peer = stream.peer_addr();
    println!("tcp echo: {peer} connected");
    let mut buffer = vec![0u8; TCP_BUFFER];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if let Err(error) = stream.write_all(&buffer[..n]).await {
                    eprintln!("tcp echo to {peer}: {error}");
                    break;
                }
            }
            Err(error) => {
                eprintln!("tcp echo from {peer}: {error}");
                break;
            }
        }
    }
    let _ = stream.shutdown().await;
    println!("tcp echo: {peer} closed");
}

async fn udp_echo_loop(mut socket: YggUdpSocket) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_BUFFER];
    loop {
        let (n, from) = socket.recv_from(&mut buffer).await?;
        if let Err(error) = socket.send_to(&buffer[..n], from).await {
            eprintln!("udp echo to {from}: {error}");
        }
    }
}

fn parse_args() -> Result<Option<Args>, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mut config = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(None);
            }
            "-c" | "--config" => {
                let path = args.next().ok_or("--config requires a path")?;
                set_config(&mut config, PathBuf::from(path))?;
            }
            _ if arg.starts_with("--config=") => {
                let path = arg.trim_start_matches("--config=");
                set_config(&mut config, PathBuf::from(path))?;
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unknown option: {arg}").into());
            }
            _ => set_config(&mut config, PathBuf::from(arg))?,
        }
    }

    Ok(Some(Args { config }))
}

fn set_config(slot: &mut Option<PathBuf>, path: PathBuf) -> Result<(), Box<dyn Error>> {
    if slot.is_some() {
        return Err("config path specified more than once".into());
    }
    if path.as_os_str().is_empty() {
        return Err("config path must not be empty".into());
    }
    *slot = Some(path);
    Ok(())
}
