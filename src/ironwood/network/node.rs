//! `Ironwood` — единый владелец. Реализует `PacketConnBase` и `PacketConn`.
//! Соединяет `Router` (топология) с `Peer` (сессии) через `session_loop_sync`.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::ironwood::{
    errors::Error,
    network::{
        config::Config,
        crypto::Crypto,
        deadline::Deadline,
        peer::{InFrame, PacketDispatcher, Peer, PeerHandle, session_loop_sync, spawn_peer},
        peers::Peers,
        router::{Router, TrafficAction},
        traffic::Traffic,
    },
    types::{
        addr::KeyAddr,
        packetconn::{AsyncConn, PacketConn as PacketConnTrait, PacketConnBase, ReadWrite},
    },
};

/// Единый владелец: конфиг, крипто, роутер, реестр пиров, локальная очередь.
pub struct Ironwood {
    config: Config,
    crypto: Arc<Crypto>,
    router: Mutex<Router>,
    peers: Mutex<Peers>,
    recv_q: Mutex<VecDeque<Traffic>>,
    recv_notify: Notify,
    deadline: Deadline,
    shutdown: CancellationToken,
    closed: AtomicBool,
}

impl Ironwood {
    /// Аналог `NewPacketConn(secret, options...)`.
    ///
    /// # Errors
    /// Возможные ошибки инициализации `Config`/`Crypto` (пока их нет — infallible).
    pub fn new(secret: &SigningKey, config: Config) -> Result<Arc<Self>, Error> {
        let crypto = Arc::new(Crypto::from_signing_key(secret.clone()));
        let router = Router::new(Arc::clone(&crypto), config.clone());
        Ok(Arc::new(Self {
            config,
            crypto,
            router: Mutex::new(router),
            peers: Mutex::new(Peers::new()),
            recv_q: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            deadline: Deadline::new(),
            shutdown: CancellationToken::new(),
            closed: AtomicBool::new(false),
        }))
    }

    fn router_lock(&self) -> MutexGuard<'_, Router> {
        self.router.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn peers_lock(&self) -> MutexGuard<'_, Peers> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn recv_lock(&self) -> MutexGuard<'_, VecDeque<Traffic>> {
        self.recv_q.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Доставить трафик в `recv_q`. Дропаем старые пакеты, если переполнено.
    fn deliver_local(&self, tr: Traffic) {
        if tr.dest != *self.crypto.public_key() {
            return;
        }
        let max = self.config.peer_max_message_size;
        {
            let mut q = self.recv_lock();
            q.push_back(tr);
            let mut total: u64 = q.iter().map(Traffic::size).sum();
            while total > max {
                if let Some(dropped) = q.pop_front() {
                    total -= dropped.size();
                } else {
                    break;
                }
            }
        }
        self.recv_notify.notify_one();
    }

    /// Общая логика dispatch. `IronwoodDispatcher` и `IronwoodDispatcherRef`
    /// делегируют сюда.
    fn dispatch_impl(&self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error> {
        match frame {
            InFrame::KeepAlive => Ok(()),
            InFrame::SigReq(req) => {
                self.router_lock().handle_request(peer, &req);
                Ok(())
            }
            InFrame::SigRes(res) => {
                // RTT сейчас ZERO; измерение — следующий шаг (в `Peer`).
                self.router_lock()
                    .handle_response(peer, &res, Duration::ZERO)
            }
            InFrame::Announce(ann) => self.router_lock().handle_announce(peer, &ann),
            InFrame::Bloom(_)
            | InFrame::PathLookup(_)
            | InFrame::PathNotify(_)
            | InFrame::PathBroken(_) => {
                // TODO: blooms/pathfinder.
                Ok(())
            }
            InFrame::Traffic(tr) => {
                let action = self.router_lock().handle_traffic(*tr);
                match action {
                    TrafficAction::Forward(p, tr) => {
                        p.send_traffic(tr);
                    }
                    TrafficAction::DeliverLocal(tr) => {
                        self.deliver_local(tr);
                    }
                    TrafficAction::Broken(_) => {
                        // TODO: pathfinder::handle_broken.
                    }
                }
                Ok(())
            }
        }
    }

    /// Зарегистрировать свежего `Peer`. `handle` — `Arc<dyn PeerHandle>`,
    /// `peer` — конкретный тип (нужен `Peers::add`).
    fn register_peer(&self, peer: &Arc<Peer>, handle: &Arc<dyn PeerHandle>) {
        self.peers_lock().add(Arc::clone(peer));
        self.router_lock().add_peer(handle);
    }

    fn unregister_peer(&self, peer: &Arc<Peer>, handle: &Arc<dyn PeerHandle>) {
        self.router_lock().remove_peer(handle);
        self.peers_lock().remove(peer);
    }
}

// ──────────────── PacketConnBase ────────────────

#[async_trait::async_trait]
impl PacketConnBase for Ironwood {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, KeyAddr)> {
        loop {
            let maybe_tr = self.recv_lock().pop_front();
            if let Some(tr) = maybe_tr {
                let n = buf.len().min(tr.payload.len());
                buf[..n].copy_from_slice(&tr.payload[..n]);
                return Ok((n, KeyAddr(tr.source)));
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => {
                    return Err(io::Error::other("closed"));
                }
                () = self.deadline.cancelled() => {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                () = self.recv_notify.notified() => {}
            }
        }
    }

    async fn send_to(&self, buf: &[u8], addr: &KeyAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other("closed"));
        }
        if (buf.len() as u64) > self.mtu() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversized"));
        }
        let tr = Traffic {
            path: Vec::new(),
            from: Vec::new(),
            source: *self.crypto.public_key(),
            dest: *addr.as_key(),
            watermark: u64::MAX,
            payload: buf.to_vec(),
        };
        let action = self.router_lock().send_traffic(tr);
        match action {
            TrafficAction::Forward(p, tr) => {
                p.send_traffic(tr);
                Ok(buf.len())
            }
            TrafficAction::DeliverLocal(tr) => {
                self.deliver_local(tr);
                Ok(buf.len())
            }
            TrafficAction::Broken(_) => {
                Err(io::Error::new(io::ErrorKind::NotFound, "peer not found"))
            }
        }
    }

    fn local_addr(&self) -> io::Result<KeyAddr> {
        Ok(KeyAddr(*self.crypto.public_key()))
    }

    fn close(&self) -> Result<(), Error> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(Error::CLOSED);
        }
        self.shutdown.cancel();
        self.recv_notify.notify_waiters();
        Ok(())
    }

    fn set_read_deadline(&self, t: Option<Instant>) -> Result<(), Error> {
        self.deadline.set(t);
        Ok(())
    }
    fn set_write_deadline(&self, _t: Option<Instant>) -> Result<(), Error> {
        Ok(())
    }
    fn set_deadline(&self, t: Option<Instant>) -> Result<(), Error> {
        self.set_read_deadline(t)?;
        self.set_write_deadline(t)
    }
}

// ──────────────── PacketConn (sync) ────────────────

impl PacketConnTrait for Ironwood {
    fn handle_conn_sync(
        &self,
        key: &VerifyingKey,
        conn: &mut dyn ReadWrite,
        prio: u8,
    ) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::CLOSED);
        }
        if self.crypto.public_key() == key {
            return Err(Error::BAD_KEY);
        }

        let (port, order) = {
            let mut peers = self.peers_lock();
            (peers.port_for(key), peers.allocate_order())
        };

        let peer = Arc::new(Peer::new(*key, port, prio, order));
        let handle: Arc<dyn PeerHandle> = peer.clone();
        self.register_peer(&peer, &handle);

        let mut dispatcher = IronwoodDispatcherRef { node: self };
        let result = session_loop_sync(
            &peer,
            conn,
            &mut dispatcher,
            self.config.peer_max_message_size,
        );

        self.unregister_peer(&peer, &handle);
        result
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn private_key(&self) -> Arc<SigningKey> {
        Arc::new(self.crypto.private_key().clone())
    }

    fn mtu(&self) -> u64 {
        self.config
            .peer_max_message_size
            .saturating_sub(Traffic::header_size())
    }

    fn send_lookup(&self, _target: &VerifyingKey) {
        // TODO: pathfinder::rumor_send_lookup.
    }
}

// ──────────────── Dispatcher ────────────────

/// Owned-диспетчер для async `spawn_conn`.
pub struct IronwoodDispatcher {
    node: Arc<Ironwood>,
}

impl PacketDispatcher for IronwoodDispatcher {
    fn dispatch(&mut self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error> {
        self.node.dispatch_impl(peer, frame)
    }
}

/// Ref-диспетчер для sync `handle_conn_sync`.
pub struct IronwoodDispatcherRef<'a> {
    node: &'a Ironwood,
}

impl PacketDispatcher for IronwoodDispatcherRef<'_> {
    fn dispatch(&mut self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error> {
        self.node.dispatch_impl(peer, frame)
    }
}

// ──────────────── Async spawn ────────────────

/// Async-обёртка над `session_loop_sync`: `spawn_peer` (reader + writer +
/// keepalive) + регистрация в `Router`/`Peers`. Возвращается, когда
/// сессия завершилась (EOF/ошибка/shutdown).
///
/// # Errors
/// - [`Error::CLOSED`] если `node` уже закрыт;
/// - [`Error::BAD_KEY`] если `key == node.public_key()`.
pub async fn spawn_conn(
    node: Arc<Ironwood>,
    key: VerifyingKey,
    conn: Box<dyn AsyncConn>,
    prio: u8,
) -> Result<(), Error> {
    if node.closed.load(Ordering::SeqCst) {
        return Err(Error::CLOSED);
    }
    if node.crypto.public_key() == &key {
        return Err(Error::BAD_KEY);
    }

    let (port, order) = {
        let mut peers = node.peers_lock();
        (peers.port_for(&key), peers.allocate_order())
    };

    let dispatcher = Box::new(IronwoodDispatcher {
        node: Arc::clone(&node),
    });
    let (peer, handle) = spawn_peer(
        key,
        port,
        prio,
        order,
        conn,
        dispatcher,
        node.config.peer_max_message_size,
        node.config.peer_keep_alive_delay,
        &node.shutdown,
    );

    let dyn_handle: Arc<dyn PeerHandle> = peer.clone();
    node.register_peer(&peer, &dyn_handle);

    let _ = handle.await;

    node.unregister_peer(&peer, &dyn_handle);
    Ok(())
}
