//! Высокоуровневый API: пиры, overlay TCP/UDP и `node_info`.
//!
//! Низкоуровневый [`crate::ironwood`] работает с IPv6-пакетами и ключами.
//! Этот модуль добавляет то, что обычно нужно приложению:
//!
//! * подключение к пирам по URI/адресу ([`Yggdrasil::peer_uri`],
//!   [`Yggdrasil::peer_tcp`]);
//! * обычные [`tokio::net::TcpStream`]/[`tokio::net::UdpSocket`] внутри
//!   yggdrasil-сети ([`Yggdrasil::tcp`], [`Yggdrasil::udp`]);
//! * TCP/UDP-серверы и клиенты прямо в процессе, без TUN и портов ОС
//!   ([`Yggdrasil::tcp_listen`], [`Yggdrasil::tcp_connect`],
//!   [`Yggdrasil::udp_bind`]);
//! * `node_info` (JSON) и запрос `node_info` у другого узла.
//!
//! [`Yggdrasil::tcp`] и [`Yggdrasil::udp`] используют TUN
//! (`YggdrasilConfig::tun`) и требуют `CAP_NET_ADMIN`/root. Пользовательский
//! стек [`Yggdrasil::tcp_listen`]/[`Yggdrasil::udp_bind`] работает без TUN:
//! IPv6-пакеты разбираются внутри процесса, а порт существует только в
//! yggdrasil. TUN по умолчанию выключен; включить его можно через
//! [`YggdrasilConfig::with_tun`].
//!
//! ```no_run
//! use std::net::Ipv6Addr;
//! use uu_yggdrasil::{YggdrasilConfig, new};
//!
//! # async fn run() -> std::io::Result<()> {
//! let mut config = YggdrasilConfig::default().with_tun();
//! config.node_info.include_peers = true;
//! let yggdrasil = new(config).await?;
//!
//! yggdrasil
//!     .peer_uri("tcp://127.0.0.1:7992?key=<64 hex>&priority=10")
//!     .await?;
//! let stream = yggdrasil.tcp("200::1".parse::<Ipv6Addr>().unwrap(), 80).await?;
//! let info = yggdrasil.node_info();
//! # let _ = (stream, info);
//! # Ok(())
//! # }
//! ```

use crate::address::{Address, addr_for_key, addr_get_key};
use crate::config::MulticastInterfaceConfig;
use crate::inproc::{Engine, YggTcpListener, YggTcpStream, YggUdpSocket};
use crate::ironwood::{
    network::{Config, Ironwood, PublicKey, handshake_async, public_key_from_bytes, spawn_conn},
    types::{
        addr::KeyAddr,
        packetconn::{PacketConn as _, PacketConnBase},
    },
};
use crate::ws;
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    fmt::Write as _,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    process::Command,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, lookup_host},
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

pub use tokio::net::{TcpStream, UdpSocket};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const NODE_INFO_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_NODE_INFO: usize = 16_384;
const MAX_BUFFERED_PACKETS: usize = 64;
const TUN_BUF_SIZE: usize = 65_575;

const TYPE_SESSION_PROTO: u8 = 2;
const TYPE_NODE_INFO_REQUEST: u8 = 1;
const TYPE_NODE_INFO_RESPONSE: u8 = 2;
const TYPE_PROTO_DEBUG: u8 = 255;

const TYPE_DEBUG_GET_SELF_REQUEST: u8 = 1;
const TYPE_DEBUG_GET_SELF_RESPONSE: u8 = 2;
const TYPE_DEBUG_GET_PEERS_REQUEST: u8 = 3;
const TYPE_DEBUG_GET_PEERS_RESPONSE: u8 = 4;
const TYPE_DEBUG_GET_TREE_REQUEST: u8 = 5;
const TYPE_DEBUG_GET_TREE_RESPONSE: u8 = 6;

const DEBUG_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);
/// Заголовок ответа: `TYPE_PROTO_DEBUG` + подтип.
const DEBUG_RESPONSE_OVERHEAD: usize = 2;
/// Префикс `TYPE_SESSION_PROTO`, который добавляет [`Ironwood::send_proto`].
const SESSION_PROTO_OVERHEAD: usize = 1;

type PendingDebug = Mutex<HashMap<(PublicKey, DebugRequest), oneshot::Sender<Vec<u8>>>>;

/// Вид удалённого служебного запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DebugRequest {
    SelfInfo,
    Peers,
    Tree,
}

impl DebugRequest {
    const fn request_type(self) -> u8 {
        match self {
            Self::SelfInfo => TYPE_DEBUG_GET_SELF_REQUEST,
            Self::Peers => TYPE_DEBUG_GET_PEERS_REQUEST,
            Self::Tree => TYPE_DEBUG_GET_TREE_REQUEST,
        }
    }

    const fn response_type(self) -> u8 {
        match self {
            Self::SelfInfo => TYPE_DEBUG_GET_SELF_RESPONSE,
            Self::Peers => TYPE_DEBUG_GET_PEERS_RESPONSE,
            Self::Tree => TYPE_DEBUG_GET_TREE_RESPONSE,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::SelfInfo => "getSelf",
            Self::Peers => "getPeers",
            Self::Tree => "getTree",
        }
    }
}

/// Настройки TUN. Если `YggdrasilConfig::tun == None`, [`Yggdrasil::tcp`] и
/// [`Yggdrasil::udp`] недоступны, но пользовательский стек
/// ([`Yggdrasil::tcp_listen`], [`Yggdrasil::udp_bind`]), пиры и `node_info`
/// работают.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Имя интерфейса (до 15 символов).
    pub name: String,
    /// MTU интерфейса. Yggdrasil обычно использует 65535.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "yggdrasil0".to_owned(),
            mtu: 65_535,
        }
    }
}

/// Настройки `node_info`.
#[derive(Debug, Clone, Default)]
pub struct NodeInfoConfig {
    /// Пользовательские поля JSON.
    pub fields: Map<String, Value>,
    /// Не добавлять `buildname`/`buildversion`/`buildplatform`/`buildarch`.
    pub privacy: bool,
    /// Добавлять в ответ `peers` — ключи и адреса текущих пиров.
    pub include_peers: bool,
}

/// Конфигурация высокоуровневого узла.
pub struct YggdrasilConfig {
    /// Долговременный ed25519-ключ узла.
    pub private_key: SigningKey,
    /// Параметры ironwood (таймауты, bloom и т.д.).
    pub network: Config,
    /// Включить TUN и overlay TCP/UDP.
    pub tun: Option<TunConfig>,
    /// Содержимое `node_info`.
    pub node_info: NodeInfoConfig,
    /// Multicast-обнаружение пиров. Пустой список выключает его.
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
}

impl YggdrasilConfig {
    /// Включить TUN с настройками по умолчанию.
    #[must_use]
    pub fn with_tun(mut self) -> Self {
        self.tun = Some(TunConfig::default());
        self
    }
}

impl Default for YggdrasilConfig {
    fn default() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed");
        Self {
            private_key: SigningKey::from_bytes(&seed),
            network: Config::default(),
            tun: None,
            node_info: NodeInfoConfig::default(),
            // Библиотечный default не занимает порты и не шлёт multicast.
            // Загрузчик конфига включает обнаружение, если секции нет.
            multicast_interfaces: Vec::new(),
        }
    }
}

/// Информация о подключённом пире.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    pub key: PublicKey,
    pub address: SocketAddr,
    pub priority: u8,
}

/// Высокоуровневый узел yggdrasil.
pub struct Yggdrasil {
    inner: Arc<Inner>,
}

/// Создать узел (сокращение для [`Yggdrasil::new`]).
///
/// # Errors
/// См. [`Yggdrasil::new`].
pub async fn new(config: YggdrasilConfig) -> io::Result<Yggdrasil> {
    Yggdrasil::new(config).await
}

pub(crate) struct Inner {
    node: Arc<Ironwood>,
    secret: SigningKey,
    key: PublicKey,
    address: Address,
    node_info: NodeInfoConfig,
    tun_enabled: bool,
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    inproc: Mutex<Option<Engine>>,
    pending_packets: Mutex<HashMap<Address, Vec<Vec<u8>>>>,
    last_lookup: Mutex<HashMap<Address, Instant>>,
    lookup_notify: Notify,
    pending_info: Mutex<HashMap<PublicKey, oneshot::Sender<Value>>>,
    pending_debug: PendingDebug,
    multicast: Mutex<Option<crate::multicast::Multicast>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown: CancellationToken,
}

impl Inner {
    pub(crate) const fn node(&self) -> &Arc<Ironwood> {
        &self.node
    }

    pub(crate) const fn secret(&self) -> &SigningKey {
        &self.secret
    }

    pub(crate) const fn key(&self) -> PublicKey {
        self.key
    }

    pub(crate) const fn address(&self) -> Address {
        self.address
    }

    pub(crate) const fn addr_to_key(&self) -> &Arc<RwLock<HashMap<Address, PublicKey>>> {
        &self.addr_to_key
    }

    pub(crate) const fn shutdown_token(&self) -> &CancellationToken {
        &self.shutdown
    }
}

impl Yggdrasil {
    /// Создать узел. Если `config.tun` задан, интерфейс создаётся сразу;
    /// для этого нужны `root/CAP_NET_ADMIN`.
    ///
    /// # Errors
    /// Ошибка создания TUN, настройки адреса/маршрута или инициализации ядра.
    #[allow(
        clippy::too_many_lines,
        clippy::unused_async,
        clippy::unused_async_trait_impl
    )]
    pub async fn new(mut config: YggdrasilConfig) -> io::Result<Self> {
        let key = config.private_key.verifying_key();
        let address = addr_for_key(key.as_bytes());

        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<PublicKey>();
        let old_notify = Arc::clone(&config.network.path_notify);
        config.network.path_notify = Arc::new(move |k| {
            let _ = notify_tx.send(*k);
            old_notify(k);
        });

        debug!(
            key = %hex(key.as_bytes()),
            address = %Ipv6Addr::from(address),
            "yggdrasil: node starting"
        );
        let node = Ironwood::new(&config.private_key, config.network)
            .map_err(|e| io::Error::other(format!("ironwood init: {e:?}")))?;

        let inner = Arc::new(Inner {
            node: Arc::clone(&node),
            secret: config.private_key.clone(),
            key,
            address,
            node_info: config.node_info,
            tun_enabled: config.tun.is_some(),
            addr_to_key: Arc::new(RwLock::new(HashMap::new())),
            inproc: Mutex::new(None),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
            pending_debug: Mutex::new(HashMap::new()),
            multicast: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            shutdown: CancellationToken::new(),
        });

        // Периодическое обслуживание router/pathfinder/session.
        {
            let node = Arc::clone(&node);
            let shutdown = inner.shutdown.clone();
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = sleep(Duration::from_millis(100)) => node.do_maintenance(),
                    }
                }
            });
            inner.push_task(task);
        }

        // Полные ключи из path-notify: addr -> key, затем разбудить
        // ожидающих и отправить пакеты, стоявшие в очереди.
        {
            let task_inner = Arc::clone(&inner);
            let task = tokio::spawn(async move {
                while let Some(key) = notify_rx.recv().await {
                    let addr = addr_for_key(key.as_bytes());
                    task_inner
                        .addr_to_key
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(addr, key);
                    task_inner.lookup_notify.notify_waiters();
                    task_inner.flush_buffered(addr).await;
                }
            });
            inner.push_task(task);
        }

        // Входящие протокольные сообщения: node_info и удалённая диагностика.
        {
            let task_inner = Arc::clone(&inner);
            let task = tokio::spawn(async move {
                while let Some((from, payload)) = task_inner.node.recv_proto().await {
                    task_inner.handle_proto(from, &payload).await;
                }
            });
            inner.push_task(task);
        }

        if let Some(tun_config) = config.tun
            && let Err(error) = inner.start_tun(&tun_config)
        {
            inner.shutdown.cancel();
            let _ = node.close();
            let tasks = inner
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain(..)
                .collect::<Vec<_>>();
            for task in tasks {
                task.abort();
            }
            return Err(error);
        }

        if !config.multicast_interfaces.is_empty() {
            match crate::multicast::start(&inner, config.multicast_interfaces) {
                Ok(multicast) => {
                    *inner
                        .multicast
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(multicast);
                }
                Err(error) => {
                    tracing::warn!(%error, "multicast: failed to start");
                }
            }
        }

        Ok(Self { inner })
    }

    /// Низкоуровневый узел (для собственных протоколов поверх IPv6).
    #[must_use]
    pub fn node(&self) -> Arc<Ironwood> {
        Arc::clone(&self.inner.node)
    }

    /// Локальный ed25519-ключ.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.inner.key
    }

    /// Локальный IPv6-адрес в yggdrasil-сети.
    #[must_use]
    pub fn address(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.inner.address)
    }

    /// Подключиться к пиру по URI.
    ///
    /// Поддерживаются `tcp://host:port`, `ws://host:port/path` и
    /// `wss://host:port/path`. Query-параметры:
    /// `key=<64 hex>`, `password=<...>`, `priority=<0..255>`, `sni=<name>`
    /// (для WSS).
    ///
    /// # Errors
    /// Некорректный URI, неподдерживаемая схема, ошибка DNS/соединения,
    /// TLS/WebSocket или handshake.
    pub async fn peer_uri(&self, uri: &str) -> io::Result<PeerInfo> {
        let parsed = PeerUri::parse(uri)?;
        let addr = resolve_first(&parsed.host, parsed.port).await?;
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer connect timed out"))??;
        stream.set_nodelay(true)?;

        match parsed.scheme {
            PeerScheme::Tcp => {
                self.inner
                    .connect_stream(stream, addr, parsed.key, &parsed.password, parsed.priority)
                    .await
            }
            PeerScheme::Ws => {
                let websocket = timeout(CONNECT_TIMEOUT, ws::client(stream, &parsed.request_uri()))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "ws handshake timed out")
                    })??;
                self.inner
                    .connect_stream(
                        websocket,
                        addr,
                        parsed.key,
                        &parsed.password,
                        parsed.priority,
                    )
                    .await
            }
            PeerScheme::Wss => {
                let tls = timeout(
                    CONNECT_TIMEOUT,
                    ws::tls_connect(stream, parsed.sni.as_deref().unwrap_or(&parsed.host)),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "wss TLS timed out"))??;
                let websocket = timeout(CONNECT_TIMEOUT, ws::client(tls, &parsed.request_uri()))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "wss handshake timed out")
                    })??;
                self.inner
                    .connect_stream(
                        websocket,
                        addr,
                        parsed.key,
                        &parsed.password,
                        parsed.priority,
                    )
                    .await
            }
        }
    }

    /// Подключиться к TCP-пиру.
    ///
    /// # Errors
    /// Ошибка TCP-соединения или handshake.
    pub async fn peer_tcp<I: Into<IpAddr>>(&self, ip: I, port: u16) -> io::Result<PeerInfo> {
        self.inner
            .connect_peer(SocketAddr::new(ip.into(), port), None, &[], 0)
            .await
    }

    /// Слушать входящие подключения пиров по URI.
    ///
    /// Поддерживаются `tcp://host:port` и `ws://host:port` с query
    /// `password=<...>` и `priority=<0..255>`. `wss://`-listener не
    /// поддерживается (как и в yggdrasil-go): используйте `ws://` за
    /// reverse proxy с TLS.
    ///
    /// # Errors
    /// Некорректный URI, неподдерживаемая схема или ошибка bind/listen.
    pub async fn listen_uri(&self, uri: &str) -> io::Result<SocketAddr> {
        let parsed = PeerUri::parse(uri)?;
        let addr = resolve_first(&parsed.host, parsed.port).await?;
        match parsed.scheme {
            PeerScheme::Tcp => {
                self.listen_tcp_options(addr, &parsed.password, parsed.priority)
                    .await
            }
            PeerScheme::Ws => {
                self.listen_ws_options(addr, &parsed.password, parsed.priority)
                    .await
            }
            PeerScheme::Wss => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WSS listener is not supported; use WS behind a TLS reverse proxy",
            )),
        }
    }

    /// Слушать входящие TCP-подключения пиров. Возвращает фактический
    /// локальный адрес (удобно с портом `0`).
    ///
    /// # Errors
    /// Ошибка bind/listen.
    pub async fn listen_tcp(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.listen_tcp_options(addr, &[], 0).await
    }

    /// Слушать входящие WebSocket-подключения пиров.
    ///
    /// # Errors
    /// Ошибка bind/listen.
    pub async fn listen_ws(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.listen_ws_options(addr, &[], 0).await
    }

    async fn listen_tcp_options(
        &self,
        addr: SocketAddr,
        password: &[u8],
        priority: u8,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let inner = Arc::clone(&self.inner);
        let password = password.to_vec();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let task_inner = Arc::clone(&inner);
                let secret = task_inner.secret.clone();
                let password = password.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let Ok(Ok(meta)) = timeout(
                        CONNECT_TIMEOUT,
                        handshake_async(&mut stream, &secret, &password, priority),
                    )
                    .await
                    else {
                        return;
                    };
                    if meta.public_key == task_inner.key() {
                        return;
                    }
                    let _ = spawn_conn(
                        Arc::clone(&task_inner.node),
                        meta.public_key,
                        Box::new(stream),
                        priority,
                    )
                    .await;
                });
            }
        });
        self.inner.push_task(task);
        Ok(local)
    }

    async fn listen_ws_options(
        &self,
        addr: SocketAddr,
        password: &[u8],
        priority: u8,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let inner = Arc::clone(&self.inner);
        let password = password.to_vec();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    break;
                };
                let task_inner = Arc::clone(&inner);
                let secret = task_inner.secret.clone();
                let password = password.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let Ok(Ok(mut websocket)) = timeout(CONNECT_TIMEOUT, ws::server(stream)).await
                    else {
                        return;
                    };
                    let Ok(Ok(meta)) = timeout(
                        CONNECT_TIMEOUT,
                        handshake_async(&mut websocket, &secret, &password, priority),
                    )
                    .await
                    else {
                        return;
                    };
                    if meta.public_key == task_inner.key() {
                        return;
                    }
                    let _ = spawn_conn(
                        Arc::clone(&task_inner.node),
                        meta.public_key,
                        Box::new(websocket),
                        priority,
                    )
                    .await;
                });
            }
        });
        self.inner.push_task(task);
        Ok(local)
    }

    /// Слушать TCP-порт внутри yggdrasil, не занимая порт ОС.
    ///
    /// Это пользовательский TCP/IP-стек: клиенты из yggdrasil подключаются к
    /// этому порту обычным TCP, а приложение получает [`YggTcpStream`].
    /// Одновременно с TUN этот режим пока не работает.
    ///
    /// # Errors
    /// Порт `0`, порт уже занят внутри этого узла, включён TUN или стек не
    /// запустился.
    pub async fn tcp_listen(&self, port: u16) -> io::Result<YggTcpListener> {
        debug!(port, address = %self.address(), "yggdrasil: TCP listen");
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP port must not be zero",
            ));
        }
        self.inner.start_inproc()?.tcp_listen(port).await
    }

    /// Подключиться по TCP через пользовательский стек, без TUN.
    ///
    /// # Errors
    /// IPv4-адрес, порт `0`, lookup или таймаут установки соединения.
    pub async fn tcp_connect<I: Into<IpAddr>>(&self, ip: I, port: u16) -> io::Result<YggTcpStream> {
        let ip = match ip.into() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "yggdrasil uses IPv6 addresses",
                ));
            }
        };
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP port must not be zero",
            ));
        }
        let key = self.inner.ensure_key(ip).await?;
        debug!(
            dest = %ip,
            port,
            key = %hex(key.as_bytes()),
            "yggdrasil: TCP connect"
        );
        self.inner
            .start_inproc()?
            .tcp_connect(ip, port, Some(key))
            .await
    }

    /// Слушать UDP-порт внутри yggdrasil, не занимая порт ОС.
    ///
    /// # Errors
    /// Порт `0`, порт уже занят внутри этого узла, включён TUN или стек не
    /// запустился.
    pub async fn udp_bind(&self, port: u16) -> io::Result<YggUdpSocket> {
        debug!(port, address = %self.address(), "yggdrasil: UDP bind");
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP port must not be zero",
            ));
        }
        self.inner
            .start_inproc()?
            .udp_bind(port, Arc::clone(&self.inner))
            .await
    }

    /// Создать QUIC-транспорт поверх yggdrasil-сети.
    ///
    /// Транспорт использует тот же узел, что и [`Self::tcp_listen`]/[`Self::udp_bind`],
    /// но не занимает порт ОС.
    ///
    /// # Errors
    /// Ошибка создания TLS-сертификата или QUIC-endpoint'а.
    pub fn quic(&self) -> io::Result<crate::quic::YggdrasilQuic> {
        crate::quic::YggdrasilQuic::new(&self.inner)
    }

    /// Открыть TCP-соединение внутри yggdrasil-сети.
    ///
    /// # Errors
    /// TUN выключен, адрес не найден path-lookup'ом, либо ошибка ОС.
    pub async fn tcp<I: Into<IpAddr>>(&self, ip: I, port: u16) -> io::Result<TcpStream> {
        let ip = match ip.into() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "yggdrasil uses IPv6 addresses",
                ));
            }
        };
        self.inner.require_tun()?;
        self.inner.ensure_key(ip).await?;
        TcpStream::connect(SocketAddr::new(IpAddr::V6(ip), port)).await
    }

    /// Открыть connected UDP-сокет внутри yggdrasil-сети.
    ///
    /// # Errors
    /// TUN выключен, адрес не найден path-lookup'ом, либо ошибка ОС.
    pub async fn udp<I: Into<IpAddr>>(&self, ip: I, port: u16) -> io::Result<UdpSocket> {
        let ip = match ip.into() {
            IpAddr::V6(ip) => ip,
            IpAddr::V4(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "yggdrasil uses IPv6 addresses",
                ));
            }
        };
        self.inner.require_tun()?;
        self.inner.ensure_key(ip).await?;
        let socket = UdpSocket::bind("[::]:0").await?;
        socket
            .connect(SocketAddr::new(IpAddr::V6(ip), port))
            .await?;
        Ok(socket)
    }

    /// `node_info` этого узла. Если в конфиге включён `include_peers`,
    /// поле `peers` заполняется текущими подключениями.
    #[must_use]
    pub fn node_info(&self) -> Value {
        self.inner.node_info_json()
    }

    /// Запросить `node_info` у другого узла.
    ///
    /// # Errors
    /// Таймаут (6 секунд), ошибка отправки или некорректный JSON.
    pub async fn node_info_for(&self, key: PublicKey) -> io::Result<Value> {
        if key == self.inner.key {
            return Ok(self.node_info());
        }
        let (tx, mut rx) = oneshot::channel();
        self.inner
            .pending_info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, tx);
        let deadline = Instant::now() + NODE_INFO_TIMEOUT;
        loop {
            if let Err(e) = self
                .inner
                .node
                .send_proto(key, &[TYPE_NODE_INFO_REQUEST])
                .await
            {
                self.inner
                    .pending_info
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&key);
                return Err(io::Error::other(format!("send node_info request: {e}")));
            }
            let retry_at = (Instant::now() + Duration::from_secs(1)).min(deadline);
            match timeout_at(retry_at, &mut rx).await {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(_)) => {
                    return Err(io::Error::other("node_info response channel closed"));
                }
                Err(_) if Instant::now() >= deadline => {
                    self.inner
                        .pending_info
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&key);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for node_info response",
                    ));
                }
                Err(_) => {}
            }
        }
    }

    /// Запросить у удалённого узла `getSelf` (`debug_remoteGetSelf`).
    ///
    /// # Errors
    /// Таймаут (6 секунд), ошибка отправки или некорректный JSON.
    pub async fn debug_remote_get_self(&self, key: PublicKey) -> io::Result<Value> {
        if key == self.inner.key {
            return Ok(self.inner.debug_self_json());
        }
        let data = self
            .inner
            .request_debug(key, DebugRequest::SelfInfo)
            .await?;
        serde_json::from_slice(&data)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Запросить у удалённого узла список пиров (`debug_remoteGetPeers`).
    ///
    /// # Errors
    /// Таймаут (6 секунд), ошибка отправки или некорректный ответ.
    pub async fn debug_remote_get_peers(&self, key: PublicKey) -> io::Result<Vec<PublicKey>> {
        if key == self.inner.key {
            return Ok(self.inner.node.peer_keys());
        }
        let data = self.inner.request_debug(key, DebugRequest::Peers).await?;
        Ok(decode_debug_keys(&data))
    }

    /// Запросить у удалённого узла ключи дерева (`debug_remoteGetTree`).
    ///
    /// # Errors
    /// Таймаут (6 секунд), ошибка отправки или некорректный ответ.
    pub async fn debug_remote_get_tree(&self, key: PublicKey) -> io::Result<Vec<PublicKey>> {
        if key == self.inner.key {
            return Ok(self.inner.node.tree_keys());
        }
        let data = self.inner.request_debug(key, DebugRequest::Tree).await?;
        Ok(decode_debug_keys(&data))
    }

    /// Закрыть узел и остановить фоновые задачи.
    pub fn close(&self) {
        self.inner.shutdown.cancel();
        let multicast = self
            .inner
            .multicast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(multicast) = multicast {
            multicast.close();
        }
        let _ = self.inner.node.close();
        for task in self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

impl Drop for Yggdrasil {
    fn drop(&mut self) {
        self.close();
    }
}

impl Inner {
    async fn connect_peer(
        &self,
        addr: SocketAddr,
        expected: Option<PublicKey>,
        password: &[u8],
        priority: u8,
    ) -> io::Result<PeerInfo> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer connect timed out"))??;
        stream.set_nodelay(true)?;
        self.connect_stream(stream, addr, expected, password, priority)
            .await
    }

    async fn connect_stream<S>(
        &self,
        mut stream: S,
        addr: SocketAddr,
        expected: Option<PublicKey>,
        password: &[u8],
        priority: u8,
    ) -> io::Result<PeerInfo>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let meta = timeout(
            CONNECT_TIMEOUT,
            handshake_async(&mut stream, &self.secret, password, priority),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer handshake timed out"))??;
        if let Some(expected) = expected
            && expected != meta.public_key
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer public key does not match URI",
            ));
        }
        let info = PeerInfo {
            key: meta.public_key,
            address: addr,
            priority,
        };
        let node = Arc::clone(&self.node);
        let key = meta.public_key;
        let task = tokio::spawn(async move {
            let _ = spawn_conn(node, key, Box::new(stream), priority).await;
        });
        self.push_task(task);
        // Дать session-loop зарегистрировать пира до возврата из API.
        for _ in 0..100 {
            if self.node.peer_keys().contains(&key) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        Ok(info)
    }

    fn push_task(&self, task: JoinHandle<()>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    fn node_info_json(&self) -> Value {
        let mut obj = self.node_info.fields.clone();
        if !self.node_info.privacy {
            obj.insert("buildname".to_owned(), json!(env!("CARGO_PKG_NAME")));
            obj.insert("buildversion".to_owned(), json!(env!("CARGO_PKG_VERSION")));
            obj.insert("buildplatform".to_owned(), json!(std::env::consts::OS));
            obj.insert("buildarch".to_owned(), json!(std::env::consts::ARCH));
        }
        if self.node_info.include_peers {
            let peers: Vec<Value> = self
                .node
                .peer_keys()
                .into_iter()
                .map(|key| {
                    json!({
                        "key": hex(key.as_bytes()),
                        "address": Ipv6Addr::from(addr_for_key(key.as_bytes())).to_string(),
                    })
                })
                .collect();
            obj.insert("peers".to_owned(), Value::Array(peers));
        }
        Value::Object(obj)
    }

    /// Обработать входящее протокольное сообщение.
    async fn handle_proto(&self, from: PublicKey, payload: &[u8]) {
        if payload.first() != Some(&TYPE_SESSION_PROTO) || payload.len() < 2 {
            return;
        }
        trace!(
            from = %hex(from.as_bytes()),
            kind = payload[1],
            bytes = payload.len(),
            "proto: message received"
        );
        match payload[1] {
            TYPE_NODE_INFO_REQUEST => self.handle_node_info_request(from).await,
            TYPE_NODE_INFO_RESPONSE => {
                trace!(
                    from = %hex(from.as_bytes()),
                    "proto: node_info response received"
                );
                let Ok(value) = serde_json::from_slice::<Value>(&payload[2..]) else {
                    return;
                };
                let tx = self
                    .pending_info
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&from);
                if let Some(tx) = tx {
                    let _ = tx.send(value);
                }
            }
            TYPE_PROTO_DEBUG => {
                let Some(&debug_type) = payload.get(2) else {
                    return;
                };
                let data = payload.get(3..).unwrap_or_default();
                self.handle_debug(from, debug_type, data).await;
            }
            other => {
                trace!(
                    from = %hex(from.as_bytes()),
                    kind = other,
                    "proto: unknown message type"
                );
            }
        }
    }

    async fn handle_node_info_request(&self, from: PublicKey) {
        trace!(
            from = %hex(from.as_bytes()),
            "proto: node_info request received"
        );
        let Ok(info) = serde_json::to_vec(&self.node_info_json()) else {
            debug!(
                from = %hex(from.as_bytes()),
                "proto: failed to serialize node_info"
            );
            return;
        };
        if info.len() > MAX_NODE_INFO {
            debug!(
                from = %hex(from.as_bytes()),
                bytes = info.len(),
                "proto: node_info response too large"
            );
            return;
        }
        let mut data = Vec::with_capacity(info.len() + 1);
        data.push(TYPE_NODE_INFO_RESPONSE);
        data.extend_from_slice(&info);
        if let Err(error) = self.node.send_proto(from, &data).await {
            debug!(
                from = %hex(from.as_bytes()),
                %error,
                "proto: failed to send node_info response"
            );
        }
    }

    /// Обработать удалённый служебный запрос или ответ.
    async fn handle_debug(&self, from: PublicKey, debug_type: u8, data: &[u8]) {
        match debug_type {
            TYPE_DEBUG_GET_SELF_REQUEST => {
                debug!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::SelfInfo.name(),
                    "remote service request"
                );
                let info = self.debug_self_json();
                match serde_json::to_vec(&info) {
                    Ok(json) => {
                        self.send_debug_response(from, DebugRequest::SelfInfo, &json)
                            .await;
                    }
                    Err(error) => {
                        debug!(
                            from = %hex(from.as_bytes()),
                            %error,
                            "proto: failed to serialize getSelf response"
                        );
                    }
                }
            }
            TYPE_DEBUG_GET_PEERS_REQUEST => {
                debug!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::Peers.name(),
                    "remote service request"
                );
                let keys = self.node.peer_keys();
                let bytes = self.encode_debug_keys(&keys);
                self.send_debug_response(from, DebugRequest::Peers, &bytes)
                    .await;
            }
            TYPE_DEBUG_GET_TREE_REQUEST => {
                debug!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::Tree.name(),
                    "remote service request"
                );
                let keys = self.node.tree_keys();
                let bytes = self.encode_debug_keys(&keys);
                self.send_debug_response(from, DebugRequest::Tree, &bytes)
                    .await;
            }
            TYPE_DEBUG_GET_SELF_RESPONSE => {
                trace!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::SelfInfo.name(),
                    "proto: debug response received"
                );
                self.resolve_debug(from, DebugRequest::SelfInfo, data.to_vec());
            }
            TYPE_DEBUG_GET_PEERS_RESPONSE => {
                trace!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::Peers.name(),
                    "proto: debug response received"
                );
                self.resolve_debug(from, DebugRequest::Peers, data.to_vec());
            }
            TYPE_DEBUG_GET_TREE_RESPONSE => {
                trace!(
                    from = %hex(from.as_bytes()),
                    request = DebugRequest::Tree.name(),
                    "proto: debug response received"
                );
                self.resolve_debug(from, DebugRequest::Tree, data.to_vec());
            }
            other => {
                trace!(
                    from = %hex(from.as_bytes()),
                    kind = other,
                    "proto: unknown debug message type"
                );
            }
        }
    }

    fn debug_self_json(&self) -> Value {
        json!({
            "key": hex(self.key.as_bytes()),
            "routing_entries": self.node.info_count().to_string(),
        })
    }

    /// Уложить ключи в ответ, не превышая MTU сессии.
    fn encode_debug_keys(&self, keys: &[PublicKey]) -> Vec<u8> {
        let mtu = usize::try_from(self.node.mtu()).unwrap_or(usize::MAX);
        let available = mtu
            .saturating_sub(SESSION_PROTO_OVERHEAD)
            .saturating_sub(DEBUG_RESPONSE_OVERHEAD);
        let max_keys = available / 32;
        let mut out = Vec::with_capacity(keys.len().min(max_keys) * 32);
        for key in keys.iter().take(max_keys) {
            out.extend_from_slice(key.as_bytes());
        }
        out
    }

    async fn send_debug_response(&self, to: PublicKey, request: DebugRequest, data: &[u8]) {
        let mut msg = Vec::with_capacity(data.len() + DEBUG_RESPONSE_OVERHEAD);
        msg.push(TYPE_PROTO_DEBUG);
        msg.push(request.response_type());
        msg.extend_from_slice(data);
        if let Err(error) = self.node.send_proto(to, &msg).await {
            debug!(
                to = %hex(to.as_bytes()),
                request = request.name(),
                %error,
                "proto: failed to send debug response"
            );
        }
    }

    fn resolve_debug(&self, from: PublicKey, request: DebugRequest, data: Vec<u8>) {
        let tx = self
            .pending_debug
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(from, request));
        if let Some(tx) = tx {
            let _ = tx.send(data);
        } else {
            trace!(
                from = %hex(from.as_bytes()),
                request = request.name(),
                "proto: unsolicited debug response"
            );
        }
    }

    async fn request_debug(&self, key: PublicKey, request: DebugRequest) -> io::Result<Vec<u8>> {
        let (tx, mut rx) = oneshot::channel();
        self.pending_debug
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((key, request), tx);

        let deadline = Instant::now() + DEBUG_REQUEST_TIMEOUT;
        loop {
            if let Err(error) = self
                .node
                .send_proto(key, &[TYPE_PROTO_DEBUG, request.request_type()])
                .await
            {
                self.remove_pending_debug(key, request);
                return Err(io::Error::other(format!(
                    "send {} request: {error}",
                    request.name()
                )));
            }
            let retry_at = (Instant::now() + Duration::from_secs(1)).min(deadline);
            match timeout_at(retry_at, &mut rx).await {
                Ok(Ok(data)) => return Ok(data),
                Ok(Err(_)) => {
                    return Err(io::Error::other(format!(
                        "{} response channel closed",
                        request.name()
                    )));
                }
                Err(_) if Instant::now() >= deadline => {
                    self.remove_pending_debug(key, request);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("timed out waiting for {} response", request.name()),
                    ));
                }
                Err(_) => {}
            }
        }
    }

    fn remove_pending_debug(&self, key: PublicKey, request: DebugRequest) {
        self.pending_debug
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(key, request));
    }

    fn require_tun(&self) -> io::Result<()> {
        if self.tun_enabled {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN is disabled; set YggdrasilConfig::tun",
            ))
        }
    }

    fn start_inproc(&self) -> io::Result<Engine> {
        if self.tun_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "in-process TCP/UDP cannot be combined with TUN yet",
            ));
        }
        let mut current = self
            .inproc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = current.as_ref() {
            return Ok(engine.clone());
        }
        debug!(address = %Ipv6Addr::from(self.address), "yggdrasil: starting in-process stack");
        let (engine, tasks) = Engine::start(
            Arc::clone(&self.node),
            self.address,
            Arc::clone(&self.addr_to_key),
            self.shutdown.clone(),
        );
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(tasks);
        *current = Some(engine.clone());
        drop(current);
        Ok(engine)
    }

    pub(crate) async fn ensure_key(&self, ip: Ipv6Addr) -> io::Result<PublicKey> {
        let addr: Address = ip.octets();
        let mapped = self
            .addr_to_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr)
            .copied();
        if let Some(key) = mapped {
            trace!(
                ip = %ip,
                key = %hex(key.as_bytes()),
                "yggdrasil: address already mapped"
            );
            return Ok(key);
        }
        debug!(ip = %ip, "yggdrasil: path lookup for address");
        let partial = addr_get_key(&addr);
        let deadline = Instant::now() + LOOKUP_TIMEOUT;
        loop {
            self.node.send_lookup_partial(&partial);
            let notified = self.lookup_notify.notified();
            let mapped = self
                .addr_to_key
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&addr)
                .copied();
            if let Some(key) = mapped {
                debug!(
                    ip = %ip,
                    key = %hex(key.as_bytes()),
                    "yggdrasil: address resolved"
                );
                return Ok(key);
            }
            trace!(ip = %ip, "yggdrasil: address not resolved yet, retrying lookup");
            let retry_at = (Instant::now() + Duration::from_millis(500)).min(deadline);
            if timeout_at(retry_at, notified).await.is_err() && Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for yggdrasil key lookup",
                ));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn start_tun(self: &Arc<Self>, config: &TunConfig) -> io::Result<()> {
        let mut tun_config = tun::Configuration::default();
        tun_config
            .tun_name(&config.name)
            .mtu(config.mtu)
            .layer(tun::Layer::L3)
            .up();
        let device = tun::create_as_async(&tun_config)
            .map_err(|e| io::Error::other(format!("create TUN: {e}")))?;

        let cidr = format!("{}/7", Ipv6Addr::from(self.address));
        run_ip(&["-6", "addr", "replace", &cidr, "dev", &config.name])?;
        run_ip(&[
            "link",
            "set",
            "dev",
            &config.name,
            "up",
            "mtu",
            &config.mtu.to_string(),
        ])?;

        let (writer, reader) = device.split()?;
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

        // TUN -> yggdrasil.
        {
            let inner = Arc::clone(self);
            let mut reader = reader;
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; TUN_BUF_SIZE];
                loop {
                    let n = match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if n < 40 || buf[0] >> 4 != 6 {
                        continue;
                    }
                    let Ok(addr) = Address::try_from(&buf[24..40]) else {
                        continue;
                    };
                    // Локальный/служебный трафик не отправляем в overlay.
                    if addr == inner.address || addr[0] == 0xfe || addr[0] == 0xff {
                        continue;
                    }
                    let key = inner
                        .addr_to_key
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&addr)
                        .copied();
                    if let Some(key) = key {
                        inner.send_packet(key, &buf[..n]).await;
                    } else {
                        let should_lookup = {
                            let mut last = inner
                                .last_lookup
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let now = Instant::now();
                            let send = last
                                .get(&addr)
                                .is_none_or(|t| now.duration_since(*t) >= Duration::from_secs(1));
                            if send {
                                last.insert(addr, now);
                            }
                            send
                        };
                        {
                            let mut pending = inner
                                .pending_packets
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            {
                                let queue = pending.entry(addr).or_default();
                                if queue.len() >= MAX_BUFFERED_PACKETS {
                                    queue.remove(0);
                                }
                                queue.push(buf[..n].to_vec());
                            }
                            drop(pending);
                        }
                        if should_lookup {
                            inner.node.send_lookup_partial(&addr_get_key(&addr));
                        }
                    }
                }
            });
            self.push_task(task);
        }

        // yggdrasil -> TUN.
        {
            let inner = Arc::clone(self);
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; TUN_BUF_SIZE];
                loop {
                    let Ok((n, _)) = inner.node.recv_from(&mut buf).await else {
                        break;
                    };
                    if n > 1 && buf[0] == 1 && tx.send(buf[1..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            });
            self.push_task(task);
        }

        // writer
        {
            let mut writer = writer;
            let task = tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if writer.write_all(&packet).await.is_err() {
                        break;
                    }
                }
            });
            self.push_task(task);
        }

        Ok(())
    }

    async fn send_packet(&self, key: PublicKey, packet: &[u8]) {
        let mut payload = Vec::with_capacity(packet.len() + 1);
        payload.push(1);
        payload.extend_from_slice(packet);
        let _ = self.node.send_to(&payload, &KeyAddr(key)).await;
    }

    async fn flush_buffered(&self, addr: Address) {
        let key = self
            .addr_to_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr)
            .copied();
        let Some(key) = key else {
            return;
        };
        let packets = self
            .pending_packets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&addr)
            .unwrap_or_default();
        for packet in packets {
            self.send_packet(key, &packet).await;
        }
    }
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn decode_debug_keys(data: &[u8]) -> Vec<PublicKey> {
    let (chunks, _) = data.as_chunks::<32>();
    chunks
        .iter()
        .filter_map(|chunk| PublicKey::from_bytes(chunk).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerScheme {
    Tcp,
    Ws,
    Wss,
}

impl PeerScheme {
    fn parse(scheme: &str) -> io::Result<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "ws" => Ok(Self::Ws),
            "wss" => Ok(Self::Wss),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported peer scheme: {scheme}"),
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

#[derive(Debug)]
struct PeerUri {
    scheme: PeerScheme,
    host: String,
    port: u16,
    path: String,
    query: String,
    key: Option<PublicKey>,
    password: Vec<u8>,
    priority: u8,
    sni: Option<String>,
}

impl PeerUri {
    fn parse(uri: &str) -> io::Result<Self> {
        let uri = uri.trim();
        if uri.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "peer URI must not be empty",
            ));
        }
        let (scheme, rest) = match uri.split_once("://") {
            Some((scheme, rest)) => (PeerScheme::parse(scheme)?, rest),
            None => (PeerScheme::Tcp, uri),
        };
        let rest = rest.split('#').next().unwrap_or(rest);
        let (authority_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, path) = match authority_and_path.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (authority_and_path, String::new()),
        };
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);

        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let (host, tail) = stripped
                .split_once(']')
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad IPv6 peer URI"))?;
            let port = tail.strip_prefix(':').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "peer URI has no port")
            })?;
            (host.to_owned(), port.to_owned())
        } else {
            let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "peer URI has no port")
            })?;
            (host.to_owned(), port.to_owned())
        };
        let port = port
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad peer port"))?;
        if host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "peer URI has no host",
            ));
        }

        let mut key = None;
        let mut password = Vec::new();
        let mut priority = 0;
        let mut sni = None;
        for item in query.split('&').filter(|item| !item.is_empty()) {
            let (name, value) = item.split_once('=').unwrap_or((item, ""));
            match name {
                "key" => {
                    let bytes = unhex(value).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "bad peer key")
                    })?;
                    key = Some(public_key_from_bytes(&bytes).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid or weak peer key")
                    })?);
                }
                "password" => password = value.as_bytes().to_vec(),
                "priority" => {
                    priority = value.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "bad peer priority")
                    })?;
                }
                "sni" if !value.is_empty() => sni = Some(value.to_owned()),
                _ => {}
            }
        }
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query: query.to_owned(),
            key,
            password,
            priority,
            sni,
        })
    }

    fn request_uri(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        let query = if self.query.is_empty() {
            String::new()
        } else {
            format!("?{}", self.query)
        };
        format!(
            "{}://{host}:{}{path}{query}",
            self.scheme.as_str(),
            self.port
        )
    }
}

async fn resolve_first(host: &str, port: u16) -> io::Result<SocketAddr> {
    lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host did not resolve"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_uri() {
        let uri = PeerUri::parse("tcp://example.com:7992?priority=7&password=secret").unwrap();
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.port, 7992);
        assert_eq!(uri.priority, 7);
        assert_eq!(uri.password, b"secret");
        assert!(uri.key.is_none());
    }

    #[test]
    fn parses_ipv6_uri_and_key() {
        let key = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let uri = PeerUri::parse(&format!("tcp://[::1]:1?key={}", hex(key.as_bytes()))).unwrap();
        assert_eq!(uri.host, "::1");
        assert_eq!(uri.port, 1);
        assert_eq!(uri.key, Some(key));
    }

    #[test]
    fn parses_ws_and_wss_uris() {
        let ws = PeerUri::parse("ws://example.com:80/ygg?priority=3").unwrap();
        assert_eq!(ws.scheme, PeerScheme::Ws);
        assert_eq!(ws.path, "/ygg");
        assert_eq!(ws.request_uri(), "ws://example.com:80/ygg?priority=3");

        let wss = PeerUri::parse("wss://[::1]:443/?sni=peer.example").unwrap();
        assert_eq!(wss.scheme, PeerScheme::Wss);
        assert_eq!(wss.sni.as_deref(), Some("peer.example"));
        assert_eq!(wss.request_uri(), "wss://[::1]:443/?sni=peer.example");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert_eq!(
            PeerUri::parse("tls://example.com:1").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn rejects_weak_peer_key() {
        let error = PeerUri::parse(
            "tcp://example.com:1?key=26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("weak"));
    }

    #[test]
    fn hex_roundtrip() {
        let key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(unhex(&hex(key.as_bytes())), Some(*key.as_bytes()));
    }

    #[test]
    fn node_info_has_build_fields_and_optional_peers() {
        let config = YggdrasilConfig::default();
        let info = NodeInfoConfig {
            fields: Map::new(),
            privacy: false,
            include_peers: true,
        };
        let inner = Inner {
            node: Ironwood::new(&config.private_key, Config::default()).unwrap(),
            secret: config.private_key.clone(),
            key: config.private_key.verifying_key(),
            address: addr_for_key(config.private_key.verifying_key().as_bytes()),
            node_info: info,
            tun_enabled: false,
            addr_to_key: Arc::new(RwLock::new(HashMap::new())),
            inproc: Mutex::new(None),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
            pending_debug: Mutex::new(HashMap::new()),
            multicast: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            shutdown: CancellationToken::new(),
        };
        let value = inner.node_info_json();
        assert!(value.get("buildname").is_some());
        assert_eq!(value.get("peers"), Some(&Value::Array(Vec::new())));
    }

    #[test]
    fn node_info_privacy_omits_build_fields() {
        let config = YggdrasilConfig::default();
        let inner = Inner {
            node: Ironwood::new(&config.private_key, Config::default()).unwrap(),
            secret: config.private_key.clone(),
            key: config.private_key.verifying_key(),
            address: addr_for_key(config.private_key.verifying_key().as_bytes()),
            node_info: NodeInfoConfig {
                fields: Map::new(),
                privacy: true,
                include_peers: false,
            },
            tun_enabled: false,
            addr_to_key: Arc::new(RwLock::new(HashMap::new())),
            inproc: Mutex::new(None),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
            pending_debug: Mutex::new(HashMap::new()),
            multicast: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            shutdown: CancellationToken::new(),
        };
        let value = inner.node_info_json();
        assert!(value.get("buildname").is_none());
        assert!(value.get("peers").is_none());
    }

    #[tokio::test]
    async fn overlay_sockets_require_tun() {
        let node = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let err = node.tcp(Ipv6Addr::LOCALHOST, 1).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        node.close();
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicU16, Ordering},
    };

    fn inproc_port() -> u16 {
        static NEXT: AtomicU16 = AtomicU16::new(21_000);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    async fn connect_pair() -> (Yggdrasil, Yggdrasil) {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let b = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let addr = a
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        b.peer_tcp(addr.ip(), addr.port()).await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn ws_peer_connects_through_listen_uri() {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let b = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let address = b.listen_uri("ws://127.0.0.1:0").await.expect("ws listener");
        let peer = a
            .peer_uri(&format!("ws://127.0.0.1:{}/", address.port()))
            .await
            .expect("ws peer");
        assert_eq!(peer.key, b.public_key());
        assert!(a.node().peer_keys().contains(&b.public_key()));
        assert!(b.node().peer_keys().contains(&a.public_key()));
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn direct_traffic_is_delivered_locally() {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let b = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let addr = a
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        b.peer_tcp(addr.ip(), addr.port()).await.unwrap();

        let payload = [1u8, 0x60, 0, 0, 0, 0];
        b.node()
            .send_to(&payload, &KeyAddr(a.public_key()))
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let (n, from) = timeout(Duration::from_secs(5), a.node().recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from.as_key(), &b.public_key());
        assert_eq!(&buf[..n], &payload);
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn partial_key_lookup_resolves_full_key() {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let b = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let addr = b
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        a.peer_tcp(addr.ip(), addr.port()).await.unwrap();
        let key = a.inner.ensure_key(b.address()).await.expect("lookup");
        assert_eq!(key, b.public_key());
        assert!(a.node().has_path(&b.public_key()));
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn node_info_between_two_nodes() {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let mut b_config = YggdrasilConfig::default();
        b_config.node_info.include_peers = true;
        let b = Yggdrasil::new(b_config).await.unwrap();
        let addr = b
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let peer = a.peer_tcp(addr.ip(), addr.port()).await.expect("peer_tcp");
        assert_eq!(peer.key, b.public_key());
        let info = a
            .node_info_for(b.public_key())
            .await
            .expect("node_info_for");
        assert!(info.get("buildname").is_some());
        let peers = info.get("peers").and_then(Value::as_array).expect("peers");
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].get("key"),
            Some(&json!(hex(a.public_key().as_bytes())))
        );
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn remote_debug_queries_between_two_nodes() {
        let a = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let b = Yggdrasil::new(YggdrasilConfig::default()).await.unwrap();
        let addr = b
            .listen_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let peer = a.peer_tcp(addr.ip(), addr.port()).await.expect("peer_tcp");
        assert_eq!(peer.key, b.public_key());

        let self_info = timeout(
            Duration::from_secs(10),
            a.debug_remote_get_self(b.public_key()),
        )
        .await
        .expect("getSelf timeout")
        .expect("getSelf");
        assert_eq!(
            self_info.get("key").and_then(Value::as_str),
            Some(hex(b.public_key().as_bytes()).as_str())
        );

        let peers = timeout(
            Duration::from_secs(10),
            a.debug_remote_get_peers(b.public_key()),
        )
        .await
        .expect("getPeers timeout")
        .expect("getPeers");
        assert_eq!(peers, vec![a.public_key()]);

        let tree = timeout(
            Duration::from_secs(10),
            a.debug_remote_get_tree(b.public_key()),
        )
        .await
        .expect("getTree timeout")
        .expect("getTree");
        assert!(tree.contains(&a.public_key()));
        assert!(tree.contains(&b.public_key()));

        a.close();
        b.close();
    }

    #[tokio::test]
    async fn inproc_tcp_echo_without_tun() {
        let (a, b) = connect_pair().await;
        let port = inproc_port();
        let mut listener = a.tcp_listen(port).await.expect("tcp_listen");
        assert_eq!(
            listener.local_addr(),
            SocketAddr::new(IpAddr::V6(a.address()), port)
        );
        let mut client = timeout(Duration::from_secs(5), b.tcp_connect(a.address(), port))
            .await
            .expect("connect timeout")
            .expect("connect");
        assert_eq!(client.peer_key(), Some(a.public_key()));
        let (mut server, peer, peer_key) =
            timeout(Duration::from_secs(5), listener.accept_with_key())
                .await
                .expect("accept timeout")
                .expect("accept");
        assert_eq!(peer, client.local_addr());
        assert_eq!(peer_key, Some(b.public_key()));
        assert_eq!(server.peer_key(), Some(b.public_key()));
        assert_eq!(server.peer_addr().ip(), IpAddr::V6(b.address()));

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(5), server.read_exact(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        timeout(Duration::from_secs(5), client.read_exact(&mut buf))
            .await
            .expect("read timeout")
            .unwrap();
        assert_eq!(&buf, b"pong");
        a.close();
        b.close();
    }

    #[tokio::test]
    async fn inproc_udp_datagrams_without_tun() {
        let (a, b) = connect_pair().await;
        let a_port = inproc_port();
        let b_port = inproc_port();
        let mut a_socket = a.udp_bind(a_port).await.expect("udp_bind a");
        let mut b_socket = b.udp_bind(b_port).await.expect("udp_bind b");
        let dest = SocketAddr::new(IpAddr::V6(a.address()), a_port);
        assert_eq!(b_socket.send_to(b"hello", dest).await.unwrap(), 5);

        let mut buf = [0u8; 32];
        let (n, from, from_key) = timeout(Duration::from_secs(5), a_socket.recv_from_key(&mut buf))
            .await
            .expect("recv timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, SocketAddr::new(IpAddr::V6(b.address()), b_port));
        assert_eq!(from_key, Some(b.public_key()));

        a_socket.send_to(b"world", from).await.unwrap();
        let (n, from, from_key) = timeout(Duration::from_secs(5), b_socket.recv_from_key(&mut buf))
            .await
            .expect("recv timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"world");
        assert_eq!(from, dest);
        assert_eq!(from_key, Some(a.public_key()));
        a.close();
        b.close();
    }
}
