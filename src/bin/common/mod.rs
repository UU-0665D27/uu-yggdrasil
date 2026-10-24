//! Общие runtime-помощники для bin-целей.

use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::debug;
use uu_yggdrasil::{Yggdrasil, config::hex, ironwood::network::PublicKey};

const PEER_RETRY_DELAY: Duration = Duration::from_secs(5);
const PEER_CHECK_DELAY: Duration = Duration::from_secs(1);
const PEER_SETTLE_DELAY: Duration = Duration::from_secs(2);

/// Поддерживать TCP-пира: подключаться при старте и переподключаться,
/// если ключ пропал из списка активных пиров.
pub async fn maintain_peer(node: Arc<Yggdrasil>, uri: String) {
    let mut connected: Option<PublicKey> = None;
    loop {
        let alive = connected.is_some_and(|key| node.node().peer_keys().contains(&key));
        if alive {
            sleep(PEER_CHECK_DELAY).await;
            continue;
        }
        if connected.is_some() {
            eprintln!("peer {uri}: disconnected, reconnecting");
            connected = None;
        }

        match node.peer_uri(&uri).await {
            Ok(info) => {
                debug!(
                    "peer {uri}: connected to {} at {}",
                    hex(info.key.as_bytes()),
                    info.address
                );
                connected = Some(info.key);
                sleep(PEER_SETTLE_DELAY).await;
            }
            Err(error) => {
                eprintln!("peer {uri}: {error}");
                sleep(PEER_RETRY_DELAY).await;
            }
        }
    }
}
