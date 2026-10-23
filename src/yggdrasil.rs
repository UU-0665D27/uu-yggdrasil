//! Высокоуровневый API: пиры, overlay TCP/UDP и `node_info`.
//!
//! Низкоуровневый [`crate::ironwood`] работает с IPv6-пакетами и ключами.
//! Этот модуль добавляет то, что обычно нужно приложению:
//!
//! * подключение к пирам по URI/адресу ([`Yggdrasil::peer_uri`],
//!   [`Yggdrasil::peer_tcp`]);
//! * обычные [`tokio::net::TcpStream`]/[`tokio::net::UdpSocket`] внутри
//!   yggdrasil-сети ([`Yggdrasil::tcp`], [`Yggdrasil::udp`]);
//! * `node_info` (JSON) и запрос `node_info` у другого узла.
//!
//! Для overlay-сокетов нужен TUN (`YggdrasilConfig::tun`) и права
//! `CAP_NET_ADMIN`/root: пакеты уходят в ядро через TUN, а ключ назначения
//! находится штатным path-lookup'ом yggdrasil. TUN по умолчанию выключен;
//! включить его можно через [`YggdrasilConfig::with_tun`].
//!
//! ```no_run
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
//! let stream = yggdrasil.tcp("200::1".parse().unwrap(), 80).await?;
//! let info = yggdrasil.node_info();
//! # let _ = (stream, info);
//! # Ok(())
//! # }
//! ```

use crate::address::{Address, addr_for_key, addr_get_key};
use crate::ironwood::{
    network::{Config, Ironwood, PublicKey, handshake_async, spawn_conn},
    types::{addr::KeyAddr, packetconn::PacketConnBase},
};
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

/// Настройки TUN. Если `YggdrasilConfig::tun == None`, overlay-сокеты
/// недоступны, но пиры и `node_info` работают.
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

struct Inner {
    node: Arc<Ironwood>,
    secret: SigningKey,
    key: PublicKey,
    address: Address,
    node_info: NodeInfoConfig,
    tun_enabled: bool,
    addr_to_key: RwLock<HashMap<Address, PublicKey>>,
    pending_packets: Mutex<HashMap<Address, Vec<Vec<u8>>>>,
    last_lookup: Mutex<HashMap<Address, Instant>>,
    lookup_notify: Notify,
    pending_info: Mutex<HashMap<PublicKey, oneshot::Sender<Value>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown: CancellationToken,
}

impl Yggdrasil {
    /// Создать узел. Если `config.tun` задан, интерфейс создаётся сразу;
    /// для этого нужны root/CAP_NET_ADMIN.
    ///
    /// # Errors
    /// Ошибка создания TUN, настройки адреса/маршрута или инициализации ядра.
    pub async fn new(mut config: YggdrasilConfig) -> io::Result<Self> {
        let key = config.private_key.verifying_key();
        let address = addr_for_key(key.as_bytes());

        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<PublicKey>();
        let old_notify = Arc::clone(&config.network.path_notify);
        config.network.path_notify = Arc::new(move |k| {
            let _ = notify_tx.send(*k);
            old_notify(k);
        });

        let node = Ironwood::new(&config.private_key, config.network)
            .map_err(|e| io::Error::other(format!("ironwood init: {e:?}")))?;

        let inner = Arc::new(Inner {
            node: Arc::clone(&node),
            secret: config.private_key.clone(),
            key,
            address,
            node_info: config.node_info,
            tun_enabled: config.tun.is_some(),
            addr_to_key: RwLock::new(HashMap::new()),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
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
            inner.tasks.lock().unwrap().push(task);
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
            inner.tasks.lock().unwrap().push(task);
        }

        // node_info request/response.
        {
            let task_inner = Arc::clone(&inner);
            let task = tokio::spawn(async move {
                while let Some((from, payload)) = task_inner.node.recv_proto().await {
                    if payload.first() != Some(&TYPE_SESSION_PROTO) || payload.len() < 2 {
                        continue;
                    }
                    match payload[1] {
                        TYPE_NODE_INFO_REQUEST => {
                            let Ok(info) = serde_json::to_vec(&task_inner.node_info_json()) else {
                                continue;
                            };
                            if info.len() > MAX_NODE_INFO {
                                continue;
                            }
                            let mut data = Vec::with_capacity(info.len() + 1);
                            data.push(TYPE_NODE_INFO_RESPONSE);
                            data.extend_from_slice(&info);
                            let _ = task_inner.node.send_proto(from, &data).await;
                        }
                        TYPE_NODE_INFO_RESPONSE => {
                            let Ok(value) = serde_json::from_slice::<Value>(&payload[2..]) else {
                                continue;
                            };
                            let tx = task_inner
                                .pending_info
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .remove(&from);
                            if let Some(tx) = tx {
                                let _ = tx.send(value);
                            }
                        }
                        _ => {}
                    }
                }
            });
            inner.tasks.lock().unwrap().push(task);
        }

        if let Some(tun_config) = config.tun {
            if let Err(error) = inner.start_tun(&tun_config) {
                inner.shutdown.cancel();
                let _ = node.close();
                for task in inner.tasks.lock().unwrap().drain(..) {
                    task.abort();
                }
                return Err(error);
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
    /// Поддерживается `tcp://host:port`. Query-параметры:
    /// `key=<64 hex>`, `password=<...>`, `priority=<0..255>`.
    ///
    /// # Errors
    /// Некорректный URI, неподдерживаемая схема, ошибка DNS/соединения
    /// или handshake.
    pub async fn peer_uri(&self, uri: &str) -> io::Result<PeerInfo> {
        let parsed = PeerUri::parse(uri)?;
        let addr = lookup_host((parsed.host.as_str(), parsed.port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer host did not resolve"))?;
        self.inner
            .connect_peer(addr, parsed.key, &parsed.password, parsed.priority)
            .await
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

    /// Слушать входящие TCP-подключения пиров. Возвращает фактический
    /// локальный адрес (удобно с портом `0`).
    ///
    /// # Errors
    /// Ошибка bind/listen.
    pub async fn listen_tcp(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let task_inner = Arc::clone(&inner);
                let secret = inner.secret.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let Ok(Ok(meta)) = timeout(
                        CONNECT_TIMEOUT,
                        handshake_async(&mut stream, &secret, &[], 0),
                    )
                    .await
                    else {
                        return;
                    };
                    let _ = spawn_conn(
                        Arc::clone(&task_inner.node),
                        meta.public_key,
                        Box::new(stream),
                        0,
                    )
                    .await;
                });
            }
        });
        self.inner.tasks.lock().unwrap().push(task);
        Ok(local)
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

    /// Закрыть узел и остановить фоновые задачи.
    pub fn close(&self) {
        self.inner.shutdown.cancel();
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
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer connect timed out"))??;
        stream.set_nodelay(true)?;
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
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        drop(tasks);
        // Дать session-loop зарегистрировать пира до возврата из API.
        for _ in 0..100 {
            if self.node.peer_keys().contains(&key) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        Ok(info)
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

    async fn ensure_key(&self, ip: Ipv6Addr) -> io::Result<PublicKey> {
        let addr: Address = ip.octets();
        if let Some(key) = self
            .addr_to_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr)
            .copied()
        {
            return Ok(key);
        }
        let partial = addr_get_key(&addr);
        let deadline = Instant::now() + LOOKUP_TIMEOUT;
        loop {
            self.node.send_lookup_partial(&partial);
            let notified = self.lookup_notify.notified();
            if let Some(key) = self
                .addr_to_key
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&addr)
                .copied()
            {
                return Ok(key);
            }
            let retry_at = (Instant::now() + Duration::from_millis(500)).min(deadline);
            if timeout_at(retry_at, notified).await.is_err() && Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for yggdrasil key lookup",
                ));
            }
        }
    }

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
                            let queue = pending.entry(addr).or_default();
                            if queue.len() >= MAX_BUFFERED_PACKETS {
                                queue.remove(0);
                            }
                            queue.push(buf[..n].to_vec());
                        }
                        if should_lookup {
                            inner.node.send_lookup_partial(&addr_get_key(&addr));
                        }
                    }
                }
            });
            self.tasks.lock().unwrap().push(task);
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
                    if n > 1 && buf[0] == 1 {
                        if tx.send(buf[1..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            });
            self.tasks.lock().unwrap().push(task);
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
            self.tasks.lock().unwrap().push(task);
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

#[derive(Debug)]
struct PeerUri {
    host: String,
    port: u16,
    key: Option<PublicKey>,
    password: Vec<u8>,
    priority: u8,
}

impl PeerUri {
    fn parse(uri: &str) -> io::Result<Self> {
        let (scheme, rest) = uri.split_once("://").unwrap_or(("tcp", uri));
        if scheme != "tcp" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported peer scheme: {scheme}"),
            ));
        }
        let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
        let authority = authority.trim_end_matches('/');
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
        for item in query.split('&').filter(|s| !s.is_empty()) {
            let (name, value) = item.split_once('=').unwrap_or((item, ""));
            match name {
                "key" => {
                    let bytes = unhex(value).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "bad peer key")
                    })?;
                    key = Some(PublicKey::from_bytes(&bytes).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "bad peer key")
                    })?);
                }
                "password" => password = value.as_bytes().to_vec(),
                "priority" => {
                    priority = value.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "bad peer priority")
                    })?;
                }
                _ => {}
            }
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            key,
            password,
            priority,
        })
    }
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
    fn rejects_non_tcp_scheme() {
        assert_eq!(
            PeerUri::parse("tls://example.com:1").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
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
            addr_to_key: RwLock::new(HashMap::new()),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
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
            addr_to_key: RwLock::new(HashMap::new()),
            pending_packets: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(HashMap::new()),
            lookup_notify: Notify::new(),
            pending_info: Mutex::new(HashMap::new()),
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
    use std::net::Ipv4Addr;

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
}
