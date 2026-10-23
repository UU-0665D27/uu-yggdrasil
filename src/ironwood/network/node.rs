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

use crate::ironwood::encrypted::{
    crypto::GroupAuth,
    session::{SessionEvent, SessionManager},
};
use crate::ironwood::network::pathfinder::Pathfinder;
use crate::ironwood::{
    errors::Error,
    network::{
        config::Config,
        crypto::{Crypto, PublicKey},
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
    pathfinder: Mutex<Pathfinder>,
    peers: Mutex<Peers>,
    sessions: Mutex<SessionManager>,
    recv_q: Mutex<VecDeque<Traffic>>,
    recv_notify: Notify,
    proto_q: Mutex<VecDeque<(PublicKey, Vec<u8>)>>,
    proto_notify: Notify,
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
        let mut router = Router::new(Arc::clone(&crypto), config.clone());
        // Сразу self-root'имся: без этого `lookup` не найдёт маршрута ни к кому.
        router.become_root();
        let pathfinder = Pathfinder::new(&crypto);
        Ok(Arc::new(Self {
            config,
            crypto,
            router: Mutex::new(router),
            pathfinder: Mutex::new(pathfinder),
            peers: Mutex::new(Peers::new()),
            sessions: Mutex::new(SessionManager::new(secret.clone(), GroupAuth::new(""))),
            recv_q: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            proto_q: Mutex::new(VecDeque::new()),
            proto_notify: Notify::new(),
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

    fn proto_lock(&self) -> MutexGuard<'_, VecDeque<(PublicKey, Vec<u8>)>> {
        self.proto_q.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sessions_lock(&self) -> MutexGuard<'_, SessionManager> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pathfinder_lock(&self) -> MutexGuard<'_, Pathfinder> {
        self.pathfinder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
    /// MTU base-слоя (без overhead шифрованной сессии).
    #[must_use]
    pub fn base_mtu(&self) -> u64 {
        self.config
            .peer_max_message_size
            .saturating_sub(Traffic::header_size())
    }

    /// Периодическое обслуживание. В Go это `_doMaintenance`; у нас пока
    /// только Bloom'ы — `_fix`/`_sendAnnounces` придут со следующим этапом.
    pub fn do_maintenance(&self) {
        let mut router = self.router_lock();
        router.do_maintenance();
        drop(router);
        self.pathfinder_lock().do_maintenance(&self.config);
        self.sessions_lock()
            .do_maintenance(std::time::Instant::now());
    }
    /// Положить расшифрованный payload в приёмную очередь.
    fn push_payload(&self, from: PublicKey, payload: Vec<u8>) {
        let tr = Traffic {
            path: Vec::new(),
            from: Vec::new(),
            source: from,
            dest: *self.crypto.public_key(),
            watermark: 0,
            payload,
        };
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

    /// Расшифровать входящий `Traffic` через session manager и выполнить
    /// его события (доставка/ответный handshake).
    fn deliver_encrypted(&self, tr: Traffic) {
        if tr.dest != *self.crypto.public_key() {
            return;
        }
        let events = {
            let mut sessions = self.sessions_lock();
            sessions.handle_data(tr.source, &tr.payload, std::time::Instant::now())
        };
        for event in events {
            match event {
                SessionEvent::Deliver { from, payload } => {
                    // typeSessionProto = 2; всё остальное — IPv6-трафик.
                    if payload.first() == Some(&2) {
                        self.proto_lock().push_back((from, payload));
                        self.proto_notify.notify_one();
                    } else {
                        self.push_payload(from, payload);
                    }
                }
                SessionEvent::Send { dest, data } => {
                    let _ = self.send_base_now(dest, data, false);
                }
            }
        }
    }

    /// Общая логика dispatch. `IronwoodDispatcher` и `IronwoodDispatcherRef`
    /// делегируют сюда.
    fn dispatch_impl(&self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error> {
        match frame {
            InFrame::Bloom(b) => {
                self.router_lock().handle_bloom(peer, &b);
                Ok(())
            }
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
            InFrame::PathLookup(lookup) => {
                let mut pf = self.pathfinder_lock();
                let mut router = self.router_lock();
                pf.handle_lookup(&mut router, peer, &lookup);
                Ok(())
            }
            InFrame::PathNotify(notify) => {
                let mut pf = self.pathfinder_lock();
                let mut router = self.router_lock();
                pf.handle_notify(&mut router, peer, &notify);
                Ok(())
            }
            InFrame::PathBroken(broken) => {
                let mut pf = self.pathfinder_lock();
                let mut router = self.router_lock();
                pf.handle_broken(&mut router, peer, &broken);
                Ok(())
            }
            InFrame::Traffic(tr) => {
                let action = self.route_traffic(*tr);
                match action {
                    TrafficAction::Forward(p, tr) => {
                        p.send_traffic(tr);
                    }
                    TrafficAction::DeliverLocal(tr) => {
                        self.deliver_encrypted(tr);
                    }
                    TrafficAction::Broken(_) => {
                        // `route_traffic` уже вызвал pathfinder::do_broken.
                    }
                }
                Ok(())
            }
        }
    }

    /// Маршрутизировать уже заполненный `Traffic` (path/from выставлены).
    fn route_traffic(&self, tr: Traffic) -> TrafficAction {
        let mut pf = self.pathfinder_lock();
        let mut router = self.router_lock();
        let action = router.handle_traffic(tr);
        if let TrafficAction::Broken(tr) = &action {
            pf.do_broken(&mut router, tr);
        }
        action
    }

    /// Количество подключённых пиров (диагностика).
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.router_lock().iter_peers().count()
    }

    /// Количество известных `RouterInfo` (диагностика).
    #[must_use]
    pub fn info_count(&self) -> usize {
        self.router_lock().infos.len()
    }

    /// Знает ли pathfinder маршрут до `key`.
    #[must_use]
    pub fn has_path(&self, key: &VerifyingKey) -> bool {
        self.pathfinder_lock().has_path(key)
    }

    /// Инициировать lookup по полному или частичному ключу.
    pub fn send_lookup_partial(&self, target: &[u8; 32]) {
        let mut pf = self.pathfinder_lock();
        let mut router = self.router_lock();
        pf.send_lookup(&mut router, *target);
    }

    /// Ключи всех подключённых пиров (без дублей).
    #[must_use]
    pub fn peer_keys(&self) -> Vec<PublicKey> {
        let mut out: Vec<PublicKey> = self.peers_lock().iter_all().map(|p| p.key()).collect();
        out.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        out.dedup();
        out
    }

    /// Следующее proto-сообщение `[2, subtype, ...]` от узла сети.
    pub async fn recv_proto(&self) -> Option<(PublicKey, Vec<u8>)> {
        loop {
            if let Some(item) = self.proto_lock().pop_front() {
                return Some(item);
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            tokio::select! {
                () = self.proto_notify.notified() => {}
                () = self.shutdown.cancelled() => return None,
            }
        }
    }

    /// Отправить proto-сообщение (добавляет `typeSessionProto = 2`).
    ///
    /// # Errors
    /// Ошибки отправки из [`Ironwood::send_to`].
    pub async fn send_proto(&self, dest: PublicKey, data: &[u8]) -> io::Result<usize> {
        let mut payload = Vec::with_capacity(data.len() + 1);
        payload.push(2);
        payload.extend_from_slice(data);
        self.send_to(&payload, &KeyAddr(dest)).await
    }

    /// Отправить пакет без pathfinder (пустой `path`), как трафик «вверх».
    /// Нужен для диагностики прямого пира.
    ///
    /// # Errors
    /// Закрытый сокет или слишком большой пакет.
    pub async fn send_direct(&self, buf: &[u8], addr: &KeyAddr) -> io::Result<usize> {
        let _ = self.send_base_now(*addr.as_key(), buf.to_vec(), true);
        Ok(buf.len())
    }

    /// Публичный ключ узла.
    #[must_use]
    pub fn public_key(&self) -> VerifyingKey {
        *self.crypto.public_key()
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
    /// Отправить уже сформированный `Traffic` через pathfinder (base-слой).
    /// Возвращает `false`, если путь неизвестен и пакет отложен.
    fn send_base_now(&self, dest: PublicKey, payload: Vec<u8>, empty_path: bool) -> bool {
        let tr = Traffic {
            path: Vec::new(),
            from: Vec::new(),
            source: *self.crypto.public_key(),
            dest,
            watermark: u64::MAX,
            payload,
        };
        // Прямой пир: не ждём tree/path-lookup, отправляем сразу.
        {
            let router = self.router_lock();
            if router.is_peer(&dest) {
                let peer = router.best_peer_for(&dest);
                drop(router);
                if let Some(peer) = peer {
                    peer.send_traffic(tr);
                    return true;
                }
            }
        }
        let routed = if empty_path {
            Some(tr)
        } else {
            let mut pf = self.pathfinder_lock();
            let mut router = self.router_lock();
            pf.handle_traffic(&mut router, tr)
        };
        let Some(tr) = routed else {
            return false;
        };
        match self.route_traffic(tr) {
            TrafficAction::Forward(p, tr) => {
                p.send_traffic(tr);
                true
            }
            TrafficAction::DeliverLocal(tr) => {
                self.deliver_encrypted(tr);
                true
            }
            TrafficAction::Broken(_) => false,
        }
    }

    /// Отправить payload через base-слой без шифрования (диагностика/тесты).
    ///
    /// # Errors
    /// Закрытый сокет или слишком большой пакет.
    pub async fn send_base(&self, buf: &[u8], addr: &KeyAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::other("closed"));
        }
        if (buf.len() as u64) > self.base_mtu() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversized"));
        }
        let _ = self.send_base_now(*addr.as_key(), buf.to_vec(), false);
        Ok(buf.len())
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
        let events = {
            let mut sessions = self.sessions_lock();
            sessions.write_to(*addr.as_key(), buf.to_vec(), std::time::Instant::now())
        };
        for event in events {
            match event {
                SessionEvent::Send { dest, data } => {
                    let _ = self.send_base_now(dest, data, false);
                }
                SessionEvent::Deliver { from, payload } => self.push_payload(from, payload),
            }
        }
        Ok(buf.len())
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
        self.proto_notify.notify_waiters();
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
        self.base_mtu()
            .saturating_sub(crate::ironwood::encrypted::session::SESSION_TRAFFIC_OVERHEAD as u64)
    }

    fn send_lookup(&self, target: &[u8; 32]) {
        let mut pf = self.pathfinder_lock();
        let mut router = self.router_lock();
        pf.send_lookup(&mut router, *target);
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
