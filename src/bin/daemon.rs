//! Полноценный демон: читает конфиг, поднимает TUN (если не выключен),
//! слушает пиров и поддерживает исходящие соединения.
//!
//! Запуск:
//!
//! ```text
//! uu-yggdrasil-daemon --config /etc/yggdrasil.json
//! uu-yggdrasil-daemon --config ./yggdrasil.json --no-tun
//! ```

#[path = "common/mod.rs"]
mod common;

use std::{env, error::Error, path::PathBuf, sync::Arc};

use uu_yggdrasil::Yggdrasil;

const HELP: &str = "\
Usage: uu-yggdrasil-daemon --config <path> [--no-tun]

  --config <path>  JSON-конфиг демона
  --no-tun         не создавать TUN, даже если он включён в конфиге
  -h, --help       показать эту справку";

struct Args {
    config: PathBuf,
    no_tun: bool,
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
    } = common::load_config(&args.config, !args.no_tun, true)?;

    let tun = yggdrasil
        .tun
        .as_ref()
        .map(|tun| format!("{} (mtu {})", tun.name, tun.mtu));
    let node = Arc::new(Yggdrasil::new(yggdrasil).await?);

    println!("yggdrasil daemon");
    println!("public key: {}", common::hex(node.public_key().as_bytes()));
    println!("address: {}", node.address());
    if let Some(tun) = tun {
        println!("tun: {tun}");
    } else {
        println!("tun: disabled");
    }
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

    println!("running; press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    println!("shutting down");
    for task in peer_tasks {
        task.abort();
    }
    node.close();
    Ok(())
}

fn parse_args() -> Result<Option<Args>, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mut config = None;
    let mut no_tun = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(None);
            }
            "--no-tun" => no_tun = true,
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

    let config = config.ok_or("missing --config <path>")?;
    Ok(Some(Args { config, no_tun }))
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
