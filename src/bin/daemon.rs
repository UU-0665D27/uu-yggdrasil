//! Полноценный демон: читает конфиг, поднимает TUN (если не выключен),
//! слушает пиров и поддерживает исходящие соединения.
//!
//! Запуск:
//!
//! ```text
//! uu-yggdrasil-daemon --config /etc/yggdrasil.toml
//! uu-yggdrasil-daemon --config ./yggdrasil.toml --no-tun
//! ```

#[path = "common/mod.rs"]
mod common;

use std::{error::Error, sync::Arc};

use clap::Parser as _;
use uu_yggdrasil::{
    Yggdrasil,
    cli::ArgsYgg,
    config::{self, LoadedConfig},
};

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
        remote_control: _,
    } = match &args.config {
        Some(path) => config::load_config(path, !args.no_tun, true)?,
        None => todo!("BUG"),
    };

    let tun = yggdrasil
        .tun
        .as_ref()
        .map(|tun| format!("{} (mtu {})", tun.name, tun.mtu));
    let node = Arc::new(Yggdrasil::new(yggdrasil).await?);

    println!("yggdrasil daemon");
    println!("public key: {}", config::hex(node.public_key().as_bytes()));
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
