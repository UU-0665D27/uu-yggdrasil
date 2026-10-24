//! QUIC поверх yggdrasil-транспорта.
//!
//! Модуль повторяет идею `yggquic`: QUIC-датаграммы передаются не через
//! системный UDP-сокет, а через зашифрованные сессии yggdrasil. Адресом пира
//! служит его публичный ключ, а `SocketAddr` — синтетический IPv6-адрес,
//! выведенный из ключа. Порты в этом адресе не имеют сетевого смысла.
//!
//! TLS используется только для QUIC handshake. Идентичность пира проверяется
//! по публичному ключу из самоподписанного сертификата, который должен
//! совпасть с ключом источника датаграммы.

mod tls;

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError, RwLock},
    task::{Context, Poll, Waker},
    time::Duration,
};

use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, IdleTimeout, TokioRuntime, TransportConfig,
    UdpSender,
    udp::{RecvMeta, Transmit},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::{
    address::{Address, addr_for_key},
    ironwood::{
        network::PublicKey,
        types::{addr::KeyAddr, packetconn::PacketConnBase},
    },
    yggdrasil::Inner,
};

/// Синтетический порт QUIC-адресов. Реальной UDP-розетки нет.
const QUIC_PORT: u16 = 4433;
/// Тип сессии yggdrasil для пользовательского трафика.
///
/// `yggdrasil-go` добавляет этот байт перед каждой QUIC-датаграммой и
/// отбрасывает датаграммы с другим первым байтом, поэтому для совместимости
/// его нужно добавлять и здесь.
const SESSION_TRAFFIC: u8 = 1;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const STREAM_QUEUE: usize = 256;
const RECV_BUFFER: usize = 65_535;

/// QUIC-транспорт узла yggdrasil.
pub struct YggdrasilQuic {
    endpoint: Endpoint,
    local: SocketAddr,
    local_key: PublicKey,
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    incoming: mpsc::Receiver<QuicStream>,
    incoming_sender: mpsc::Sender<QuicStream>,
    connections: Arc<tokio::sync::Mutex<HashMap<PublicKey, QuicConnection>>>,
    dial_lock: tokio::sync::Mutex<()>,
    shutdown: CancellationToken,
}

impl YggdrasilQuic {
    pub(crate) fn new(inner: &Inner) -> io::Result<Self> {
        let secret = inner.secret().clone();
        let local_key = inner.key();
        let local_address = Ipv6Addr::from(inner.address());
        let addr_to_key = Arc::clone(inner.addr_to_key());
        let shutdown = inner.shutdown_token().child_token();

        let mut transport = TransportConfig::default();
        let idle = IdleTimeout::try_from(MAX_IDLE_TIMEOUT)
            .map_err(|error| io::Error::other(format!("QUIC idle timeout: {error}")))?;
        transport.max_idle_timeout(Some(idle));
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        let transport = Arc::new(transport);
        let tls = tls::build(&secret, Arc::clone(&transport))?;

        let local = SocketAddr::new(IpAddr::V6(local_address), QUIC_PORT);
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let socket = YggUdpSocket::new(Arc::clone(&addr_to_key), local, send_tx);

        spawn_receive_pump(socket.clone(), Arc::clone(inner.node()), shutdown.clone());
        spawn_send_pump(Arc::clone(inner.node()), send_rx, shutdown.clone());

        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(tls.server),
            Box::new(socket),
            Arc::new(TokioRuntime),
        )?;
        endpoint.set_default_client_config(tls.client);

        let (incoming_tx, incoming) = mpsc::channel(STREAM_QUEUE);
        let connections = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        spawn_accept_loop(
            endpoint.clone(),
            Arc::clone(&addr_to_key),
            Arc::clone(&connections),
            incoming_tx.clone(),
            shutdown.clone(),
        );

        debug!(
            address = %local,
            key = %crate::config::hex(local_key.as_bytes()),
            "quic: transport started"
        );

        Ok(Self {
            endpoint,
            local,
            local_key,
            addr_to_key,
            incoming,
            incoming_sender: incoming_tx,
            connections,
            dial_lock: tokio::sync::Mutex::new(()),
            shutdown,
        })
    }

    /// Локальный ключ узла.
    #[must_use]
    pub const fn local_key(&self) -> PublicKey {
        self.local_key
    }

    /// Синтетический локальный адрес QUIC.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Принять входящий QUIC-поток.
    ///
    /// # Errors
    /// Транспорт остановлен.
    pub async fn accept(&mut self) -> io::Result<QuicStream> {
        self.incoming.recv().await.ok_or_else(transport_closed)
    }

    /// Открыть QUIC-соединение с пиром или переиспользовать существующее.
    ///
    /// # Errors
    /// Таймаут handshake, ошибка TLS/QUIC или неверный ключ пира.
    pub async fn connect(&self, peer: &PublicKey) -> io::Result<QuicConnection> {
        let _dial = self.dial_lock.lock().await;

        let cached = {
            let connections = self.connections.lock().await;
            connections.get(peer).cloned()
        };
        if let Some(connection) = cached
            && connection.inner.close_reason().is_none()
        {
            trace!(
                peer = %crate::config::hex(peer.as_bytes()),
                "quic: reuse connection"
            );
            return Ok(connection);
        }
        self.connections.lock().await.remove(peer);

        let address = addr_for_key(peer.as_bytes());
        self.addr_to_key
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(address, *peer);
        let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), QUIC_PORT);

        debug!(
            peer = %crate::config::hex(peer.as_bytes()),
            remote = %socket,
            "quic: dial"
        );
        let connecting = self
            .endpoint
            .connect(socket, "yggdrasil")
            .map_err(|error| io::Error::other(format!("QUIC connect: {error}")))?;
        let connection = timeout(HANDSHAKE_TIMEOUT, connecting)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
            .map_err(|error| io::Error::other(format!("QUIC handshake: {error}")))?;

        if !verify_peer(&connection, *peer) {
            connection.close(0u32.into(), b"peer key mismatch");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QUIC peer certificate does not match yggdrasil source key",
            ));
        }

        let connection = QuicConnection {
            inner: connection,
            peer: *peer,
        };

        {
            let mut connections = self.connections.lock().await;
            if let Some(existing) = connections.get(peer).cloned()
                && existing.inner.close_reason().is_none()
            {
                connection.inner.close(0u32.into(), b"duplicate");
                return Ok(existing);
            }
            connections.insert(*peer, connection.clone());
        }
        tokio::spawn(stream_loop(
            connection.clone(),
            self.incoming_sender.clone(),
            Arc::clone(&self.connections),
            self.shutdown.clone(),
        ));

        Ok(connection)
    }
}

impl Drop for YggdrasilQuic {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.endpoint.close(0u32.into(), b"transport dropped");
    }
}

/// QUIC-соединение с конкретным узлом.
#[derive(Clone)]
pub struct QuicConnection {
    inner: quinn::Connection,
    peer: PublicKey,
}

impl fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicConnection")
            .field("peer", &crate::config::hex(self.peer.as_bytes()))
            .field("remote", &self.inner.remote_address())
            .finish()
    }
}

impl QuicConnection {
    /// Публичный ключ пира.
    #[must_use]
    pub const fn peer_key(&self) -> PublicKey {
        self.peer
    }

    /// Синтетический адрес пира.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Открыть двунаправленный поток.
    ///
    /// # Errors
    /// Соединение закрыто или исчерпан лимит потоков.
    pub async fn open_bi(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .inner
            .open_bi()
            .await
            .map_err(|error| io::Error::other(format!("QUIC open stream: {error}")))?;
        trace!(
            peer = %crate::config::hex(self.peer.as_bytes()),
            "quic: stream opened"
        );
        Ok(QuicStream::new(self.peer, send, recv))
    }

    /// Закрыть соединение.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code.into(), reason);
    }
}

/// Двунаправленный QUIC-поток.
pub struct QuicStream {
    peer: PublicKey,
    inner: tokio::io::Join<quinn::RecvStream, quinn::SendStream>,
}

impl QuicStream {
    fn new(peer: PublicKey, send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            peer,
            inner: tokio::io::join(recv, send),
        }
    }

    /// Публичный ключ пира.
    #[must_use]
    pub const fn peer_key(&self) -> PublicKey {
        self.peer
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn add_traffic_prefix(data: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(data.len() + 1);
    datagram.push(SESSION_TRAFFIC);
    datagram.extend_from_slice(data);
    datagram
}

fn strip_traffic_prefix(datagram: &[u8]) -> &[u8] {
    datagram
        .strip_prefix(&[SESSION_TRAFFIC])
        .unwrap_or(datagram)
}

fn spawn_receive_pump(
    socket: YggUdpSocket,
    node: Arc<crate::ironwood::network::Ironwood>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUFFER];
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                result = node.recv_from(&mut buf) => {
                    let Ok((n, from)) = result else { break };
                    let key = *from.as_key();
                    let address = addr_for_key(key.as_bytes());
                    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), QUIC_PORT);
                    socket
                        .addr_to_key
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(address, key);
                    let payload = strip_traffic_prefix(&buf[..n]);
                    if payload.is_empty() {
                        continue;
                    }
                    trace!(
                        key = %crate::config::hex(key.as_bytes()),
                        bytes = payload.len(),
                        "quic: datagram received"
                    );
                    socket.push(Vec::from(payload), addr);
                }
            }
        }
        socket.wake();
    });
}

fn spawn_send_pump(
    node: Arc<crate::ironwood::network::Ironwood>,
    mut rx: mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let item = tokio::select! {
                () = shutdown.cancelled() => break,
                item = rx.recv() => item,
            };
            let Some((key, data)) = item else { break };
            trace!(
                peer = %crate::config::hex(key.as_bytes()),
                bytes = data.len(),
                "quic: datagram send"
            );
            let datagram = add_traffic_prefix(&data);
            if let Err(error) = node.send_to(&datagram, &KeyAddr(key)).await {
                debug!(
                    peer = %crate::config::hex(key.as_bytes()),
                    %error,
                    "quic: datagram send failed"
                );
            }
        }
    });
}

fn spawn_accept_loop(
    endpoint: Endpoint,
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    connections: Arc<tokio::sync::Mutex<HashMap<PublicKey, QuicConnection>>>,
    incoming: mpsc::Sender<QuicStream>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = shutdown.cancelled() => break,
                accepted = endpoint.accept() => accepted,
            };
            let Some(incoming_connection) = accepted else {
                break;
            };
            let remote = incoming_connection.remote_address();
            let Some(peer) = key_for_socket(&addr_to_key, remote) else {
                debug!(%remote, "quic: incoming from unknown address");
                incoming_connection.refuse();
                continue;
            };
            let connections = Arc::clone(&connections);
            let incoming = incoming.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                handle_incoming(incoming_connection, peer, connections, incoming, shutdown).await;
            });
        }
        debug!("quic: accept loop stopped");
    });
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    peer: PublicKey,
    connections: Arc<tokio::sync::Mutex<HashMap<PublicKey, QuicConnection>>>,
    incoming_tx: mpsc::Sender<QuicStream>,
    shutdown: CancellationToken,
) {
    let remote = incoming.remote_address();
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            debug!(%remote, %error, "quic: incoming accept failed");
            return;
        }
    };
    let connection = match timeout(HANDSHAKE_TIMEOUT, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            debug!(%remote, %error, "quic: incoming handshake failed");
            return;
        }
        Err(_) => {
            debug!(%remote, "quic: incoming handshake timed out");
            return;
        }
    };

    if !verify_peer(&connection, peer) {
        debug!(
            peer = %crate::config::hex(peer.as_bytes()),
            %remote,
            "quic: incoming peer certificate mismatch"
        );
        connection.close(0u32.into(), b"peer key mismatch");
        return;
    }

    let connection = QuicConnection {
        inner: connection,
        peer,
    };
    {
        let mut connections = connections.lock().await;
        if let Some(old) = connections.insert(peer, connection.clone()) {
            old.inner.close(0u32.into(), b"replaced");
        }
    }
    debug!(
        peer = %crate::config::hex(peer.as_bytes()),
        %remote,
        "quic: incoming connection accepted"
    );
    stream_loop(connection, incoming_tx, connections, shutdown).await;
}

async fn stream_loop(
    connection: QuicConnection,
    incoming: mpsc::Sender<QuicStream>,
    connections: Arc<tokio::sync::Mutex<HashMap<PublicKey, QuicConnection>>>,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = connection.inner.accept_bi() => accepted,
        };
        match accepted {
            Ok((send, recv)) => {
                let stream = QuicStream::new(connection.peer, send, recv);
                trace!(
                    peer = %crate::config::hex(connection.peer.as_bytes()),
                    "quic: stream accepted"
                );
                if incoming.send(stream).await.is_err() {
                    break;
                }
            }
            Err(error) => {
                debug!(
                    peer = %crate::config::hex(connection.peer.as_bytes()),
                    %error,
                    "quic: stream accept stopped"
                );
                break;
            }
        }
    }

    {
        let mut connections = connections.lock().await;
        if connections
            .get(&connection.peer)
            .is_some_and(|c| c.inner.stable_id() == connection.inner.stable_id())
        {
            connections.remove(&connection.peer);
        }
    }
    connection.inner.close(0u32.into(), b"closed");
}

fn verify_peer(connection: &quinn::Connection, expected: PublicKey) -> bool {
    let Some(identity) = connection.peer_identity() else {
        return false;
    };
    let Ok(identity) = identity.downcast::<quinn::rustls::crypto::Identity<'static>>() else {
        return false;
    };
    let quinn::rustls::crypto::Identity::X509(certificates) = *identity else {
        return false;
    };
    tls::certificate_key(&certificates.end_entity) == Some(expected)
}

fn key_for_socket(
    addr_to_key: &RwLock<HashMap<Address, PublicKey>>,
    remote: SocketAddr,
) -> Option<PublicKey> {
    let IpAddr::V6(ip) = remote.ip() else {
        return None;
    };
    addr_to_key
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&ip.octets())
        .copied()
}

fn transport_closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC transport is closed")
}

struct RecvState {
    queue: VecDeque<(Vec<u8>, SocketAddr)>,
    waker: Option<Waker>,
}

#[derive(Clone)]
struct YggUdpSocket {
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    local: SocketAddr,
    send: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
    recv: Arc<Mutex<RecvState>>,
}

impl YggUdpSocket {
    fn new(
        addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
        local: SocketAddr,
        send: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
    ) -> Self {
        Self {
            addr_to_key,
            local,
            send,
            recv: Arc::new(Mutex::new(RecvState {
                queue: VecDeque::new(),
                waker: None,
            })),
        }
    }

    fn push(&self, data: Vec<u8>, addr: SocketAddr) {
        let waker = {
            let mut state = self.recv.lock().unwrap_or_else(PoisonError::into_inner);
            state.queue.push_back((data, addr));
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn wake(&self) {
        let waker = {
            let mut state = self.recv.lock().unwrap_or_else(PoisonError::into_inner);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl fmt::Debug for YggUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YggUdpSocket")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for YggUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(YggUdpSender {
            addr_to_key: Arc::clone(&self.addr_to_key),
            local: self.local,
            send: self.send.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buf) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(meta) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let mut state = self.recv.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(received) = state.queue.pop_front() else {
            state.waker = Some(cx.waker().clone());
            drop(state);
            return Poll::Pending;
        };
        drop(state);
        let (data, addr) = received;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        let mut received_meta = RecvMeta::default();
        received_meta.addr = addr;
        received_meta.len = n;
        received_meta.stride = n;
        *meta = received_meta;
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct YggUdpSender {
    addr_to_key: Arc<RwLock<HashMap<Address, PublicKey>>>,
    local: SocketAddr,
    send: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
}

impl YggUdpSender {
    fn send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let IpAddr::V6(ip) = transmit.destination.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "yggdrasil QUIC supports IPv6 only",
            ));
        };
        if transmit.contents.len() > RECV_BUFFER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC datagram is too large",
            ));
        }
        let key = self
            .addr_to_key
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ip.octets())
            .copied()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no yggdrasil key for QUIC destination",
                )
            })?;
        trace!(
            %self.local,
            remote = %transmit.destination,
            bytes = transmit.contents.len(),
            "quic: socket send"
        );
        self.send
            .send((key, transmit.contents.to_vec()))
            .map_err(|_| transport_closed())
    }
}

impl UdpSender for YggUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().send(transmit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Yggdrasil, YggdrasilConfig, ironwood::network::spawn_conn};
    use ed25519_dalek::SigningKey;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::Instant,
    };

    #[test]
    fn traffic_prefix_is_added_and_stripped() {
        let data = b"\xc0initial-quic-datagram";
        let datagram = add_traffic_prefix(data);
        assert_eq!(datagram.first(), Some(&SESSION_TRAFFIC));
        assert_eq!(strip_traffic_prefix(&datagram), data);
    }

    #[test]
    fn unprefixed_datagram_is_accepted() {
        let data = b"\xc0legacy-datagram";
        assert_eq!(strip_traffic_prefix(data), data);
    }

    async fn connect_nodes(a: &Yggdrasil, b: &Yggdrasil) {
        let (socket_a, socket_b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        socket_a.set_nonblocking(true).expect("nonblocking a");
        socket_b.set_nonblocking(true).expect("nonblocking b");
        let stream_a = tokio::net::UnixStream::from_std(socket_a).expect("tokio a");
        let stream_b = tokio::net::UnixStream::from_std(socket_b).expect("tokio b");
        let node_a = a.node();
        let node_b = b.node();
        let key_a = a.public_key();
        let key_b = b.public_key();
        let _task_a = tokio::spawn(async move {
            let _ = spawn_conn(node_a, key_b, Box::new(stream_a), 0).await;
        });
        let _task_b = tokio::spawn(async move {
            let _ = spawn_conn(node_b, key_a, Box::new(stream_b), 0).await;
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while a.node().peer_count() != 1 || b.node().peer_count() != 1 {
            assert!(Instant::now() < deadline, "nodes did not peer");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn node(seed: u8) -> YggdrasilConfig {
        YggdrasilConfig {
            private_key: SigningKey::from_bytes(&[seed; 32]),
            ..YggdrasilConfig::default()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn two_nodes_exchange_streams() {
        let a = Yggdrasil::new(node(0x31)).await.expect("node a");
        let b = Yggdrasil::new(node(0x32)).await.expect("node b");
        connect_nodes(&a, &b).await;

        let mut server = a.quic().expect("quic a");
        let client = b.quic().expect("quic b");
        let connection = client.connect(&a.public_key()).await.expect("connect");
        assert_eq!(connection.peer_key(), a.public_key());

        let mut client_stream = connection.open_bi().await.expect("open stream");
        client_stream
            .write_all(b"hello over quic")
            .await
            .expect("write");
        client_stream.shutdown().await.expect("shutdown");
        let mut server_stream = timeout(Duration::from_secs(5), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        assert_eq!(server_stream.peer_key(), b.public_key());
        let mut payload = Vec::new();
        server_stream.read_to_end(&mut payload).await.expect("read");
        assert_eq!(payload, b"hello over quic");

        let mut second = connection.open_bi().await.expect("second stream");
        second.write_all(b"second").await.expect("second write");
        second.shutdown().await.expect("second shutdown");
        let mut second_in = timeout(Duration::from_secs(5), server.accept())
            .await
            .expect("second accept timeout")
            .expect("second accept");
        let mut payload = Vec::new();
        second_in
            .read_to_end(&mut payload)
            .await
            .expect("second read");
        assert_eq!(payload, b"second");

        a.close();
        b.close();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_key_is_verified() {
        let a = Yggdrasil::new(node(0x41)).await.expect("node a");
        let b = Yggdrasil::new(node(0x42)).await.expect("node b");
        connect_nodes(&a, &b).await;

        let _server = a.quic().expect("quic a");
        let client = b.quic().expect("quic b");
        let connection = timeout(Duration::from_secs(5), client.connect(&a.public_key()))
            .await
            .expect("connect timeout")
            .expect("connect");

        assert!(verify_peer(&connection.inner, a.public_key()));
        assert!(!verify_peer(&connection.inner, b.public_key()));
        assert!(!verify_peer(
            &connection.inner,
            SigningKey::from_bytes(&[0x43; 32]).verifying_key()
        ));

        a.close();
        b.close();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connection_is_reused() {
        let a = Yggdrasil::new(node(0x51)).await.expect("node a");
        let b = Yggdrasil::new(node(0x52)).await.expect("node b");
        connect_nodes(&a, &b).await;

        let _server = a.quic().expect("quic a");
        let client = b.quic().expect("quic b");
        let first = timeout(Duration::from_secs(5), client.connect(&a.public_key()))
            .await
            .expect("first connect timeout")
            .expect("first connect");
        let second = timeout(Duration::from_secs(5), client.connect(&a.public_key()))
            .await
            .expect("second connect timeout")
            .expect("second connect");

        assert_eq!(first.inner.stable_id(), second.inner.stable_id());
        assert!(second.inner.close_reason().is_none());

        a.close();
        b.close();
    }
}
