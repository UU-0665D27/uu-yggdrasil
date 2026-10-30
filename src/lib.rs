pub mod address;
pub mod cli;
pub mod config;
pub mod inproc;
pub mod ironwood;
pub mod multicast;
pub mod quic;
pub mod uu;
mod ws;
pub mod yggdrasil;

pub use config::MulticastInterfaceConfig;
pub use inproc::{YggTcpListener, YggTcpStream, YggUdpSocket};
pub use quic::{QuicConnection, QuicStream, YggdrasilQuic};
pub use yggdrasil::{
    NodeInfoConfig, PeerInfo, TcpStream, TunConfig, UdpSocket, Yggdrasil, YggdrasilConfig, new,
};

/// Инициализировать `tracing` для бинарников и примеров.
///
/// Уровень задаётся `RUST_LOG`; по умолчанию — `uu_yggdrasil=debug`.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}
