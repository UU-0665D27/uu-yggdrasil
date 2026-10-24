//! Пользовательский TCP/IP-стек для yggdrasil.
//!
//! Пакеты yggdrasil (`[1] + IPv6`) подаются в [`smoltcp`], поэтому TCP и UDP
//! работают без TUN и без занятия порта в операционной системе. Наружу
//! отдаются обычные асинхронные потоки/датаграммы.

use crate::address::{Address, addr_for_key, addr_get_key};
use crate::ironwood::{
    network::{Ironwood, PublicKey},
    types::{addr::KeyAddr, packetconn::PacketConnBase},
};
use crate::yggdrasil::Inner;
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as RxTokenTrait,
        TxToken as TxTokenTrait,
    },
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv6Address},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const LOOKUP_RETRY: Duration = Duration::from_millis(500);
const MAX_PACKET: usize = 65_535;
const TCP_RX_BUFFER: usize = 64 * 1024;
const TCP_TX_BUFFER: usize = 64 * 1024;
const UDP_PACKET_COUNT: usize = 64;
const UDP_BUFFER: usize = 64 * 1024;
// 65 535 (максимальный IPv6-пакет) − 40 (IPv6) − 8 (UDP).
const UDP_DATAGRAM_MAX: usize = 65_487;
const READ_QUEUE: usize = 64;
const WRITE_QUEUE_MAX: usize = 1024 * 1024;

/// TCP-сервер внутри yggdrasil.
///
/// Создаётся через [`crate::Yggdrasil::tcp_listen`]. Порт существует только
/// внутри процесса: в системе он не открывается.
pub struct YggTcpListener {
    id: u64,
    local: SocketAddr,
    rx: mpsc::UnboundedReceiver<YggTcpStream>,
    cmd: mpsc::UnboundedSender<Command>,
}

impl YggTcpListener {
    /// Принять входящее TCP-соединение.
    ///
    /// # Errors
    /// Пользовательский стек остановлен.
    pub async fn accept(&mut self) -> io::Result<(YggTcpStream, SocketAddr)> {
        let stream = self.rx.recv().await.ok_or_else(engine_closed)?;
        let peer = stream.peer_addr();
        Ok((stream, peer))
    }

    /// Локальный адрес, на котором слушает сервер.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for YggTcpListener {
    fn drop(&mut self) {
        let _ = self.cmd.send(Command::RemoveTcpListener { id: self.id });
    }
}

/// TCP-поток внутри yggdrasil.
pub struct YggTcpStream {
    id: u64,
    local: SocketAddr,
    peer: SocketAddr,
    read_rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    pending_pos: usize,
    cmd: mpsc::UnboundedSender<Command>,
    closed: bool,
}

impl YggTcpStream {
    /// Адрес удалённой стороны.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Локальный адрес соединения.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn shutdown(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.cmd.send(Command::TcpClose { id: self.id });
        }
    }
}

impl Drop for YggTcpStream {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl AsyncRead for YggTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending_pos < self.pending.len() {
            let available = &self.pending[self.pending_pos..];
            let n = available.len().min(buf.remaining());
            buf.put_slice(&available[..n]);
            self.pending_pos += n;
            if self.pending_pos == self.pending.len() {
                self.pending.clear();
                self.pending_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.pending = data;
                    self.pending_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for YggTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP stream is shut down",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let cmd = Command::TcpWrite {
            id: self.id,
            data: buf.to_vec(),
        };
        self.cmd.send(cmd).map_or_else(
            |_| Poll::Ready(Err(engine_closed())),
            |()| Poll::Ready(Ok(buf.len())),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown();
        Poll::Ready(Ok(()))
    }
}

/// UDP-сокет внутри yggdrasil.
///
/// Создаётся через [`crate::Yggdrasil::udp_bind`]. Порт существует только
/// внутри процесса: в системе он не открывается.
pub struct YggUdpSocket {
    id: u64,
    local: SocketAddr,
    rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    cmd: mpsc::UnboundedSender<Command>,
    inner: Arc<Inner>,
}

impl YggUdpSocket {
    /// Локальный адрес сокета.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Получить датаграмму и адрес отправителя.
    ///
    /// # Errors
    /// Пользовательский стек остановлен.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (data, addr) = self.rx.recv().await.ok_or_else(engine_closed)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, addr))
    }

    /// Отправить датаграмму. Перед отправкой выполняется path-lookup адреса.
    ///
    /// # Errors
    /// IPv4-адрес, слишком большая датаграмма, lookup или остановленный стек.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let IpAddr::V6(ip) = addr.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "yggdrasil uses IPv6 addresses",
            ));
        };
        if buf.len() > UDP_DATAGRAM_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP datagram is too large",
            ));
        }
        self.inner.ensure_key(ip).await?;
        self.cmd
            .send(Command::UdpSend {
                id: self.id,
                dest: ip,
                port: addr.port(),
                data: buf.to_vec(),
            })
            .map_err(|_| engine_closed())?;
        Ok(buf.len())
    }
}

impl Drop for YggUdpSocket {
    fn drop(&mut self) {
        let _ = self.cmd.send(Command::RemoveUdp { id: self.id });
    }
}

/// Запущенный пользовательский стек.
#[derive(Clone)]
pub(crate) struct Engine {
    tx: mpsc::UnboundedSender<Command>,
    address: Ipv6Addr,
}

impl Engine {
    pub(crate) fn start(
        node: Arc<Ironwood>,
        address: Address,
        addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
        shutdown: CancellationToken,
    ) -> (Self, Vec<JoinHandle<()>>) {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);
        let engine = Self {
            tx: cmd_tx.clone(),
            address: Ipv6Addr::from(address),
        };

        let pump = {
            let node = Arc::clone(&node);
            let addr_to_key = Arc::clone(&addr_to_key);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_PACKET + 1];
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        result = node.recv_from(&mut buf) => {
                            let Ok((n, from)) = result else {
                                break;
                            };
                            if n <= 1 || buf[0] != 1 {
                                continue;
                            }
                            let key = *from.as_key();
                            let addr = addr_for_key(key.as_bytes());
                            addr_to_key
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .insert(addr, key);
                            let packet = buf[1..n].to_vec();
                            if incoming_tx.send(Incoming { packet }).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        };

        let state = State::new(
            node,
            address,
            addr_to_key,
            cmd_tx,
            cmd_rx,
            incoming_rx,
            shutdown,
        );
        let task = tokio::spawn(state.run());
        (engine, vec![pump, task])
    }

    pub(crate) async fn tcp_listen(&self, port: u16) -> io::Result<YggTcpListener> {
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(Command::AddTcpListener {
            port,
            accepted: accepted_tx,
            reply: reply_tx,
        })?;
        let id = reply_rx.await.map_err(|_| engine_closed())??;
        Ok(YggTcpListener {
            id,
            local: SocketAddr::new(IpAddr::V6(self.address), port),
            rx: accepted_rx,
            cmd: self.tx.clone(),
        })
    }

    pub(crate) async fn tcp_connect(&self, dest: Ipv6Addr, port: u16) -> io::Result<YggTcpStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(Command::TcpConnect {
            dest,
            port,
            reply: reply_tx,
        })?;
        timeout(CONNECT_TIMEOUT, reply_rx)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))?
            .map_err(|_| engine_closed())?
    }

    pub(crate) async fn udp_bind(&self, port: u16, inner: Arc<Inner>) -> io::Result<YggUdpSocket> {
        let (tx, rx) = mpsc::channel(READ_QUEUE);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(Command::AddUdp {
            port,
            rx: tx,
            reply: reply_tx,
        })?;
        let id = reply_rx.await.map_err(|_| engine_closed())??;
        Ok(YggUdpSocket {
            id,
            local: SocketAddr::new(IpAddr::V6(self.address), port),
            rx,
            cmd: self.tx.clone(),
            inner,
        })
    }

    fn send(&self, command: Command) -> io::Result<()> {
        self.tx.send(command).map_err(|_| engine_closed())
    }
}

enum Command {
    AddTcpListener {
        port: u16,
        accepted: mpsc::UnboundedSender<YggTcpStream>,
        reply: oneshot::Sender<io::Result<u64>>,
    },
    RemoveTcpListener {
        id: u64,
    },
    TcpWrite {
        id: u64,
        data: Vec<u8>,
    },
    TcpClose {
        id: u64,
    },
    TcpConnect {
        dest: Ipv6Addr,
        port: u16,
        reply: oneshot::Sender<io::Result<YggTcpStream>>,
    },
    AddUdp {
        port: u16,
        rx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        reply: oneshot::Sender<io::Result<u64>>,
    },
    RemoveUdp {
        id: u64,
    },
    UdpSend {
        id: u64,
        dest: Ipv6Addr,
        port: u16,
        data: Vec<u8>,
    },
}

struct Incoming {
    packet: Vec<u8>,
}

struct PendingTx {
    packet: Vec<u8>,
    deadline: Instant,
    last_lookup: Instant,
}

struct Listener {
    id: u64,
    port: u16,
    handle: SocketHandle,
    accepted: mpsc::UnboundedSender<YggTcpStream>,
}

struct Conn {
    id: u64,
    handle: SocketHandle,
    local: SocketAddr,
    peer: SocketAddr,
    read_tx: Option<mpsc::Sender<Vec<u8>>>,
    read_rx: Option<mpsc::Receiver<Vec<u8>>>,
    connect_reply: Option<oneshot::Sender<io::Result<YggTcpStream>>>,
    connect_deadline: Option<Instant>,
    write: VecDeque<Vec<u8>>,
    write_bytes: usize,
    close_requested: bool,
    close_sent: bool,
    read_closed: bool,
}

struct UdpState {
    handle: SocketHandle,
    rx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    write: VecDeque<(IpEndpoint, Vec<u8>)>,
}

struct State {
    node: Arc<Ironwood>,
    address: Address,
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    iface: Interface,
    device: YggDevice,
    sockets: SocketSet<'static>,
    cmd_tx: mpsc::UnboundedSender<Command>,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    incoming_rx: mpsc::Receiver<Incoming>,
    shutdown: CancellationToken,
    listeners: HashMap<u64, Listener>,
    conns: HashMap<u64, Conn>,
    udp: HashMap<u64, UdpState>,
    pending_tx: VecDeque<PendingTx>,
    next_id: u64,
    next_port: u16,
}

impl State {
    fn new(
        node: Arc<Ironwood>,
        address: Address,
        addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
        cmd_tx: mpsc::UnboundedSender<Command>,
        cmd_rx: mpsc::UnboundedReceiver<Command>,
        incoming_rx: mpsc::Receiver<Incoming>,
        shutdown: CancellationToken,
    ) -> Self {
        let mut device = YggDevice::new();
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = u64::from_le_bytes(
            address[..8]
                .try_into()
                .expect("yggdrasil address has at least 8 bytes"),
        );
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(Ipv6Address::from(address)), 7))
                .expect("yggdrasil IPv6 address");
        });
        Self {
            node,
            address,
            addr_to_key,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            cmd_tx,
            cmd_rx,
            incoming_rx,
            shutdown,
            listeners: HashMap::new(),
            conns: HashMap::new(),
            udp: HashMap::new(),
            pending_tx: VecDeque::new(),
            next_id: 1,
            next_port: 49_152,
        }
    }

    async fn run(mut self) {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                packet = self.incoming_rx.recv() => {
                    let Some(packet) = packet else { break };
                    self.device.rx.push_back(packet.packet);
                }
                command = self.cmd_rx.recv() => {
                    let Some(command) = command else { break };
                    self.command(command);
                }
                _ = ticker.tick() => {}
            }
            self.poll();
            self.flush().await;
        }
    }

    fn poll(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.poll_listeners();
        self.poll_conns();
        self.poll_udp();
    }

    fn poll_listeners(&mut self) {
        let mut ready = Vec::new();
        for listener in self.listeners.values_mut() {
            let state = self.sockets.get_mut::<tcp::Socket>(listener.handle).state();
            if state == tcp::State::Established {
                let handle = listener.handle;
                let remote = self
                    .sockets
                    .get_mut::<tcp::Socket>(handle)
                    .remote_endpoint();
                let new_handle = add_listener_socket(&mut self.sockets, listener.port);
                if let Ok(new_handle) = new_handle {
                    listener.handle = new_handle;
                    ready.push((
                        listener.id,
                        listener.handle,
                        listener.port,
                        listener.accepted.clone(),
                        handle,
                        remote,
                    ));
                }
            } else if !self
                .sockets
                .get_mut::<tcp::Socket>(listener.handle)
                .is_open()
                && let Ok(new_handle) = add_listener_socket(&mut self.sockets, listener.port)
            {
                listener.handle = new_handle;
            }
        }
        for (listener_id, new_handle, port, accepted, handle, remote) in ready {
            let Some(remote) = remote.map(endpoint_to_socket) else {
                self.sockets.remove(handle);
                continue;
            };
            let id = self.id();
            let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(self.address)), port);
            let (read_tx, read_rx) = mpsc::channel(READ_QUEUE);
            let stream = YggTcpStream {
                id,
                local,
                peer: remote,
                read_rx,
                pending: Vec::new(),
                pending_pos: 0,
                cmd: self.cmd_tx.clone(),
                closed: false,
            };
            self.conns.insert(
                id,
                Conn {
                    id,
                    handle,
                    local,
                    peer: remote,
                    read_tx: Some(read_tx),
                    read_rx: None,
                    connect_reply: None,
                    connect_deadline: None,
                    write: VecDeque::new(),
                    write_bytes: 0,
                    close_requested: false,
                    close_sent: false,
                    read_closed: false,
                },
            );
            if accepted.send(stream).is_err() {
                // Приёмник закрыт (listener уже удалён). Закрываем и
                // принятое соединение, и новый слушающий сокет.
                if let Some(conn) = self.conns.remove(&id) {
                    self.sockets.remove(conn.handle);
                }
                self.sockets.remove(new_handle);
                self.listeners.remove(&listener_id);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn poll_conns(&mut self) {
        let now = Instant::now();
        let mut remove = Vec::new();
        for conn in self.conns.values_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            let state = socket.state();
            if let Some(deadline) = conn.connect_deadline
                && now >= deadline
            {
                if let Some(reply) = conn.connect_reply.take() {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP connect timed out",
                    )));
                }
                socket.close();
                remove.push(conn.id);
                continue;
            }
            if conn.connect_reply.is_some() {
                if state == tcp::State::Established {
                    if let Some(reply) = conn.connect_reply.take()
                        && let Some(read_rx) = conn.read_rx.take()
                    {
                        conn.connect_deadline = None;
                        let stream = YggTcpStream {
                            id: conn.id,
                            local: conn.local,
                            peer: conn.peer,
                            read_rx,
                            pending: Vec::new(),
                            pending_pos: 0,
                            cmd: self.cmd_tx.clone(),
                            closed: false,
                        };
                        let _ = reply.send(Ok(stream));
                    }
                } else if !socket.is_open() {
                    if let Some(reply) = conn.connect_reply.take() {
                        let _ = reply.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "TCP connection failed",
                        )));
                    }
                    remove.push(conn.id);
                    continue;
                }
            }

            if let Some(read_tx) = &conn.read_tx
                && socket.can_recv()
            {
                let result = socket.recv(|data| {
                    if data.is_empty() {
                        return (0, false);
                    }
                    match read_tx.try_send(data.to_vec()) {
                        Ok(()) => (data.len(), false),
                        Err(_) => (0, true),
                    }
                });
                match result {
                    Ok(true) | Err(tcp::RecvError::Finished) => {
                        conn.read_tx = None;
                        conn.read_closed = true;
                    }
                    Ok(false) | Err(tcp::RecvError::InvalidState) => {}
                }
            }
            if !socket.may_recv() && !conn.read_closed && conn.connect_reply.is_none() {
                conn.read_tx = None;
                conn.read_closed = true;
            }

            while socket.can_send() {
                let Some(front) = conn.write.front_mut() else {
                    break;
                };
                match socket.send_slice(front) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.write_bytes = conn.write_bytes.saturating_sub(n);
                        if n == front.len() {
                            conn.write.pop_front();
                        } else {
                            front.drain(..n);
                        }
                    }
                    Err(_) => {
                        conn.close_requested = true;
                        break;
                    }
                }
            }
            if conn.close_requested && !conn.close_sent && conn.write.is_empty() {
                socket.close();
                conn.close_sent = true;
            }
            if !socket.is_open() {
                remove.push(conn.id);
            }
        }
        for id in remove {
            if let Some(conn) = self.conns.remove(&id) {
                self.sockets.remove(conn.handle);
            }
        }
    }

    fn poll_udp(&mut self) {
        for state in self.udp.values_mut() {
            let socket = self.sockets.get_mut::<udp::Socket>(state.handle);
            while socket.can_recv() {
                let Ok((data, meta)) = socket.recv() else {
                    break;
                };
                let addr = endpoint_to_socket(meta.endpoint);
                if state.rx.try_send((data.to_vec(), addr)).is_err() {
                    break;
                }
            }
            while let Some((endpoint, data)) = state.write.front() {
                if socket.send_slice(data, *endpoint).is_err() {
                    break;
                }
                state.write.pop_front();
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn command(&mut self, command: Command) {
        match command {
            Command::AddTcpListener {
                port,
                accepted,
                reply,
            } => {
                let result = if self
                    .listeners
                    .values()
                    .any(|listener| listener.port == port)
                {
                    Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "TCP port is already bound",
                    ))
                } else {
                    add_listener_socket(&mut self.sockets, port).map(|handle| {
                        let id = self.id();
                        self.listeners.insert(
                            id,
                            Listener {
                                id,
                                port,
                                handle,
                                accepted,
                            },
                        );
                        id
                    })
                };
                let _ = reply.send(result);
            }
            Command::RemoveTcpListener { id } => {
                if let Some(listener) = self.listeners.remove(&id) {
                    self.sockets.remove(listener.handle);
                }
            }
            Command::TcpWrite { id, data } => {
                if let Some(conn) = self.conns.get_mut(&id) {
                    if conn.write_bytes.saturating_add(data.len()) > WRITE_QUEUE_MAX {
                        conn.close_requested = true;
                    } else {
                        conn.write_bytes += data.len();
                        conn.write.push_back(data);
                    }
                }
            }
            Command::TcpClose { id } => {
                if let Some(conn) = self.conns.get_mut(&id) {
                    conn.close_requested = true;
                }
            }
            Command::TcpConnect { dest, port, reply } => {
                self.connect(dest, port, reply);
            }
            Command::AddUdp { port, rx, reply } => {
                let result = if self.udp.values().any(|state| {
                    self.sockets
                        .get::<udp::Socket>(state.handle)
                        .endpoint()
                        .port
                        == port
                }) {
                    Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "UDP port is already bound",
                    ))
                } else {
                    add_udp_socket(&mut self.sockets, port).map(|handle| {
                        let id = self.id();
                        self.udp.insert(
                            id,
                            UdpState {
                                handle,
                                rx,
                                write: VecDeque::new(),
                            },
                        );
                        id
                    })
                };
                let _ = reply.send(result);
            }
            Command::RemoveUdp { id } => {
                if let Some(state) = self.udp.remove(&id) {
                    self.sockets.remove(state.handle);
                }
            }
            Command::UdpSend {
                id,
                dest,
                port,
                data,
            } => {
                if let Some(state) = self.udp.get_mut(&id) {
                    state
                        .write
                        .push_back((IpEndpoint::new(IpAddress::Ipv6(dest), port), data));
                }
            }
        }
    }

    fn connect(
        &mut self,
        dest: Ipv6Addr,
        port: u16,
        reply: oneshot::Sender<io::Result<YggTcpStream>>,
    ) {
        let mut socket = new_tcp_socket();
        socket.set_nagle_enabled(false);
        let local_port = self.ephemeral_port();
        let remote = endpoint_to_socket(IpEndpoint::new(IpAddress::Ipv6(dest), port));
        if let Err(error) = socket.connect(
            self.iface.context(),
            (IpAddress::Ipv6(dest), port),
            local_port,
        ) {
            let _ = reply.send(Err(io::Error::other(format!(
                "TCP connect failed: {error:?}"
            ))));
            return;
        }
        let handle = self.sockets.add(socket);
        let id = self.id();
        let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(self.address)), local_port);
        let (read_tx, read_rx) = mpsc::channel(READ_QUEUE);
        self.conns.insert(
            id,
            Conn {
                id,
                handle,
                local,
                peer: remote,
                read_tx: Some(read_tx),
                read_rx: Some(read_rx),
                connect_reply: Some(reply),
                connect_deadline: Some(Instant::now() + CONNECT_TIMEOUT),
                write: VecDeque::new(),
                write_bytes: 0,
                close_requested: false,
                close_sent: false,
                read_closed: false,
            },
        );
    }

    async fn flush(&mut self) {
        while let Some(packet) = self.device.tx.pop_front() {
            self.send_packet(packet).await;
        }
        let mut pending = VecDeque::new();
        while let Some(mut item) = self.pending_tx.pop_front() {
            let addr = packet_destination(&item.packet);
            let key = addr.and_then(|addr| {
                self.addr_to_key
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&addr)
                    .copied()
            });
            if let Some(key) = key {
                let _ = self.send_raw(key, &item.packet).await;
            } else if Instant::now() < item.deadline {
                if item.last_lookup.elapsed() >= LOOKUP_RETRY {
                    if let Some(addr) = addr {
                        self.node.send_lookup_partial(&addr_get_key(&addr));
                    }
                    item.last_lookup = Instant::now();
                }
                pending.push_back(item);
            }
        }
        self.pending_tx = pending;
    }

    async fn send_packet(&mut self, packet: Vec<u8>) {
        let Some(addr) = packet_destination(&packet) else {
            return;
        };
        let key = self
            .addr_to_key
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr)
            .copied();
        if let Some(key) = key {
            let _ = self.send_raw(key, &packet).await;
        } else {
            self.node.send_lookup_partial(&addr_get_key(&addr));
            self.pending_tx.push_back(PendingTx {
                packet,
                deadline: Instant::now() + LOOKUP_TIMEOUT,
                last_lookup: Instant::now(),
            });
        }
    }

    async fn send_raw(&self, key: PublicKey, packet: &[u8]) -> io::Result<()> {
        let mut payload = Vec::with_capacity(packet.len() + 1);
        payload.push(1);
        payload.extend_from_slice(packet);
        let _ = self.node.send_to(&payload, &KeyAddr(key)).await?;
        Ok(())
    }

    const fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                49_152
            } else {
                port.saturating_add(1)
            };
            let used = self.conns.values().any(|conn| conn.local.port() == port)
                || self
                    .listeners
                    .values()
                    .any(|listener| listener.port == port);
            if !used {
                return port;
            }
        }
    }
}

struct YggDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl YggDevice {
    const fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

impl Device for YggDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        Some((RxToken { buffer }, TxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MAX_PACKET;
        capabilities.max_burst_size = None;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

struct RxToken {
    buffer: Vec<u8>,
}

impl RxTokenTrait for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct TxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxTokenTrait for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx.push_back(buffer);
        result
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]),
    )
}

fn add_listener_socket(sockets: &mut SocketSet<'static>, port: u16) -> io::Result<SocketHandle> {
    let mut socket = new_tcp_socket();
    socket
        .listen(port)
        .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, format!("listen: {error:?}")))?;
    Ok(sockets.add(socket))
}

fn add_udp_socket(sockets: &mut SocketSet<'static>, port: u16) -> io::Result<SocketHandle> {
    let rx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_COUNT],
        vec![0u8; UDP_BUFFER],
    );
    let tx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_COUNT],
        vec![0u8; UDP_BUFFER],
    );
    let mut socket = udp::Socket::new(rx, tx);
    socket
        .bind(port)
        .map_err(|error| io::Error::new(io::ErrorKind::AddrInUse, format!("bind: {error:?}")))?;
    Ok(sockets.add(socket))
}

fn packet_destination(packet: &[u8]) -> Option<Address> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    Address::try_from(&packet[24..40]).ok()
}

const fn endpoint_to_socket(endpoint: IpEndpoint) -> SocketAddr {
    let IpAddress::Ipv6(ip) = endpoint.addr;
    SocketAddr::new(IpAddr::V6(ip), endpoint.port)
}

fn engine_closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "yggdrasil overlay engine is stopped",
    )
}
