pub mod types;

use crate::ironwood::{
    errors::Error,
    network::{
        Bloom,
        bloomfilter::Blooms,
        config::Config,
        crypto::{Crypto, PublicKey, public_key_less},
        peer::PeerHandle,
        traffic::Traffic,
        wire::PeerPort,
    },
};
use ed25519_dalek::{Signature, Signer};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
pub use types::{RouterAnnounce, RouterInfo, RouterSigReq, RouterSigRes};

/// `time.Duration(^uint32(0))` из Go — задержка ещё не замерена.
pub const ROUTER_UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);

/// `routerPath { root, path }`.
#[derive(Debug, Clone)]
pub struct RouterPath {
    pub root: PublicKey,
    pub path: Vec<PeerPort>,
}

struct PeerEntry {
    handle: Arc<dyn PeerHandle>,
}

/// Результат `Router::handle_traffic` — кто исполняет действие.
pub enum TrafficAction {
    /// Переслать next-hop'у.
    Forward(Arc<dyn PeerHandle>, Traffic),
    /// Трафик адресован нам — доставить в `recv_q`.
    DeliverLocal(Traffic),
    /// Маршрут потерян — pathfinder сгенерирует `pathBroken`.
    Broken(Traffic),
}

impl std::fmt::Debug for TrafficAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward(p, tr) => f
                .debug_struct("Forward")
                .field("next_hop", &p.key())
                .field("traffic", tr)
                .finish(),
            Self::DeliverLocal(tr) => f.debug_tuple("DeliverLocal").field(tr).finish(),
            Self::Broken(tr) => f.debug_tuple("Broken").field(tr).finish(),
        }
    }
}

struct Candidate {
    key: PublicKey,
    handle: Arc<dyn PeerHandle>,
    dist: u64,
    cost: u64,
    prio: u8,
    order: u64,
}

/// Identity пира по адресу данных (без vtable). `Arc<dyn PeerHandle>`
/// держит объект по стабильному адресу; адрес уникален на время жизни `Arc`.
fn peer_identity(p: &dyn PeerHandle) -> usize {
    std::ptr::from_ref(p).cast::<()>() as usize
}

fn arc_identity(p: &Arc<dyn PeerHandle>) -> usize {
    Arc::as_ptr(p).cast::<()>() as usize
}

/// `struct router`.
pub struct Router {
    crypto: Arc<Crypto>,
    config: Config,

    pub infos: HashMap<PublicKey, RouterInfo>,
    cache: HashMap<PublicKey, RouterPath>,

    peers: HashMap<PublicKey, Vec<PeerEntry>>,
    lags: HashMap<usize, Duration>,
    requests: HashMap<PublicKey, RouterSigReq>,
    responses: HashMap<PublicKey, RouterSigRes>,
    responded: HashSet<usize>,
    sent: HashMap<PublicKey, HashSet<PublicKey>>,

    blooms: Blooms,
    refresh: bool,
}

impl Router {
    #[must_use]
    pub fn new(crypto: Arc<Crypto>, config: Config) -> Self {
        Self {
            crypto,
            config,
            infos: HashMap::new(),
            cache: HashMap::new(),
            peers: HashMap::new(),
            lags: HashMap::new(),
            requests: HashMap::new(),
            responses: HashMap::new(),
            responded: HashSet::new(),
            sent: HashMap::new(),
            blooms: Blooms::new(),
            refresh: false,
        }
    }

    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    #[must_use]
    pub const fn crypto(&self) -> &Arc<Crypto> {
        &self.crypto
    }

    pub fn reset_cache(&mut self) {
        self.cache.clear();
    }

    // ────────────── Announce / SigReq / SigRes ──────────────

    #[must_use]
    pub fn new_req(&self) -> RouterSigReq {
        let mut nonce = [0u8; 8];
        let _ = getrandom::fill(&mut nonce);
        let seq = self
            .infos
            .get(self.crypto.public_key())
            .map_or(0, |i| i.res.req.seq)
            + 1;
        RouterSigReq {
            seq,
            nonce: u64::from_be_bytes(nonce),
        }
    }
    /// `func (bs *blooms) xKey(key)` — трансформация ключа для Bloom'а.
    #[must_use]
    pub fn x_key(&self, key: &PublicKey) -> [u8; 32] {
        (self.config.bloom_transform)(key)
    }
    pub fn handle_bloom(&mut self, peer: &dyn PeerHandle, b: &Bloom) {
        self.blooms.handle_bloom(&peer.key(), b.clone());
    }
    pub fn become_root(&mut self) -> bool {
        let req = self.new_req();
        let self_key = *self.crypto.public_key();

        let unsigned = RouterSigRes {
            req,
            port: 0,
            psig: Signature::from_bytes(&[0u8; 64]),
        };
        let psig = self
            .crypto
            .private_key()
            .sign(&unsigned.bytes_for_sig(&self_key, &self_key));

        let res = RouterSigRes { req, port: 0, psig };
        let ann = RouterAnnounce {
            key: self_key,
            parent: self_key,
            res,
            sig: psig,
        };
        self.update(&ann)
    }

    /// Принять/отклонить announce. Порядок проверок **обязан** совпадать
    /// на всех узлах. Сбрасывает `cache` и `sent[*][ann.key]` при успехе.
    pub fn update(&mut self, ann: &RouterAnnounce) -> bool {
        if let Some(info) = self.infos.get(&ann.key) {
            match ann.res.req.seq.cmp(&info.res.req.seq) {
                Ordering::Less => return false,
                Ordering::Greater => {}
                Ordering::Equal => {
                    if public_key_less(&info.parent, &ann.parent) {
                        return false;
                    }
                    let parent_better = public_key_less(&ann.parent, &info.parent);
                    let same_parent_and_nonce_better =
                        ann.parent == info.parent && ann.res.req.nonce < info.res.req.nonce;
                    if !(parent_better || same_parent_and_nonce_better) {
                        return false;
                    }
                }
            }
        }

        self.cache.clear();
        for sent in self.sent.values_mut() {
            sent.remove(&ann.key);
        }

        let info = RouterInfo {
            parent: ann.parent,
            res: ann.res,
            sig: ann.sig,
        };
        let is_self = ann.key == *self.crypto.public_key();
        self.infos.insert(ann.key, info);

        if is_self {
            self.refresh = true;
        }
        true
    }

    /// `ProtoSigReq`: строим подписанный `res` и шлём назад.
    pub fn handle_request(&mut self, peer: &dyn PeerHandle, req: &RouterSigReq) {
        let self_key = *self.crypto.public_key();
        let peer_key = peer.key();

        let placeholder = RouterSigRes {
            req: *req,
            port: peer.port(),
            psig: Signature::from_bytes(&[0u8; 64]),
        };
        let psig = self
            .crypto
            .private_key()
            .sign(&placeholder.bytes_for_sig(&peer_key, &self_key));

        let res = RouterSigRes {
            req: *req,
            port: peer.port(),
            psig,
        };
        peer.send_sig_res(&res);
    }

    /// `ProtoSigRes`: проверка подписи + обновление `responses`/`responded`/`lags`.
    ///
    /// # Errors
    /// [`Error::BAD_MESSAGE`] если подпись не сходится.
    pub fn handle_response(
        &mut self,
        peer: &dyn PeerHandle,
        res: &RouterSigRes,
        rtt: Duration,
    ) -> Result<(), Error> {
        let self_key = *self.crypto.public_key();
        let peer_key = peer.key();
        if !res.check(&self_key, &peer_key) {
            return Err(Error::BAD_MESSAGE);
        }

        let key = peer_key;
        let peer_id = peer_identity(peer);

        if !self.responses.contains_key(&key)
            && let Some(our_req) = self.requests.get(&key)
            && *our_req == res.req
        {
            self.responses.insert(key, *res);
        }

        if let Some(our_req) = self.requests.get(&key)
            && *our_req == res.req
            && self.responded.insert(peer_id)
        {
            let lag = self
                .lags
                .get(&peer_id)
                .copied()
                .unwrap_or(ROUTER_UNKNOWN_LATENCY);
            let next = if lag == ROUTER_UNKNOWN_LATENCY {
                rtt * 2
            } else {
                let prev = lag;
                lag * 7 / 8 + rtt.min(prev * 2) / 8
            };
            self.lags.insert(peer_id, next);
        }
        Ok(())
    }

    /// `ProtoAnnounce`: проверка подписи + `update` + `sent`-трекинг.
    /// В случае, если наш info лучше присланного, шлём его обратно.
    ///
    /// # Errors
    /// [`Error::BAD_MESSAGE`] если подпись не сходится.
    pub fn handle_announce(
        &mut self,
        peer: &dyn PeerHandle,
        ann: &RouterAnnounce,
    ) -> Result<(), Error> {
        if !ann.check() {
            return Err(Error::BAD_MESSAGE);
        }
        if self.update(ann) {
            if ann.key == *self.crypto.public_key() {
                self.refresh = true;
            }
            self.sent.entry(peer.key()).or_default().insert(ann.key);
        } else {
            let new_info = RouterInfo {
                parent: ann.parent,
                res: ann.res,
                sig: ann.sig,
            };
            if let Some(old) = self.infos.get(&ann.key) {
                self.sent.entry(peer.key()).or_default().insert(ann.key);
                if new_info != *old {
                    peer.send_announce(&old.get_announce(ann.key));
                }
            }
        }
        Ok(())
    }

    // ────────────── Traffic ──────────────

    /// `ProtoTraffic`: маршрутизация + `watermark`-обновление.
    pub fn handle_traffic(&mut self, mut tr: Traffic) -> TrafficAction {
        let self_key = *self.crypto.public_key();
        let mut wm = tr.watermark;
        let next = self.lookup(&tr.path, Some(&mut wm));
        tr.watermark = wm;

        if let Some(p) = next {
            return TrafficAction::Forward(p, tr);
        }
        if tr.dest == self_key {
            return TrafficAction::DeliverLocal(tr);
        }
        TrafficAction::Broken(tr)
    }

    /// `sendTraffic(tr)` — упрощённая версия (без pathfinder-кэша).
    pub fn send_traffic(&mut self, tr: Traffic) -> TrafficAction {
        self.handle_traffic(tr)
    }

    // ────────────── Peer management ──────────────

    /// `add_peer`: регистрирует сессию. `true` — ключ новый.
    pub fn add_peer(&mut self, peer: &Arc<dyn PeerHandle>) -> bool {
        let key = peer.key();
        let peer_id = arc_identity(peer);
        let is_new = !self.peers.contains_key(&key);

        self.peers.entry(key).or_default().push(PeerEntry {
            handle: Arc::clone(peer),
        });
        self.lags.insert(peer_id, ROUTER_UNKNOWN_LATENCY);

        if is_new {
            self.sent.insert(key, HashSet::new());
            self.blooms.add_info(key);
        } else {
            let resent: Vec<PublicKey> = self
                .sent
                .get(&key)
                .map_or_default(|s| s.iter().copied().collect());
            for k in resent {
                if let Some(info) = self.infos.get(&k) {
                    peer.send_announce(&info.get_announce(k));
                }
            }
        }

        if !self.requests.contains_key(&key) {
            let req = self.new_req();
            self.requests.insert(key, req);
        }
        let req = self.requests[&key];
        self.responded.remove(&peer_id);
        peer.send_sig_req(&req);

        is_new
    }

    /// `remove_peer`: снимает сессию с учёта.
    pub fn remove_peer(&mut self, peer: &Arc<dyn PeerHandle>) {
        let key = peer.key();
        let peer_id = arc_identity(peer);

        if let Some(list) = self.peers.get_mut(&key) {
            list.retain(|e| arc_identity(&e.handle) != peer_id);
            if list.is_empty() {
                self.peers.remove(&key);
                self.sent.remove(&key);
                self.requests.remove(&key);
                self.responses.remove(&key);
                self.blooms.remove_info(&key); // ← добавь
            } else {
                // Ре-отправить текущий `send` bloom остающимся пирам этого ключа.
                let bloom_to_send = self
                    .blooms
                    .iter()
                    .find(|(k, _)| **k == key)
                    .map(|(_, i)| i.send.clone());
                if let Some(b) = bloom_to_send {
                    let peers: Vec<Arc<dyn PeerHandle>> =
                        list.iter().map(|e| Arc::clone(&e.handle)).collect();
                    for p in peers {
                        p.send_bloom(&b);
                    }
                }
            }
        }
        self.lags.remove(&peer_id);
        self.responded.remove(&peer_id);
    }

    pub fn iter_peers(&self) -> impl Iterator<Item = &Arc<dyn PeerHandle>> {
        self.peers
            .values()
            .flat_map(|v| v.iter().map(|e| &e.handle))
    }

    // ────────────── Tree ──────────────

    #[must_use]
    pub fn get_root_and_dists(
        &self,
        dest: PublicKey,
    ) -> Option<(PublicKey, HashMap<PublicKey, u64>)> {
        let mut dists = HashMap::new();
        let mut next = dest;
        let mut depth = 0u64;
        loop {
            if dists.contains_key(&next) {
                return None;
            }
            let info = self.infos.get(&next)?;
            dists.insert(next, depth);
            if info.parent == next {
                return Some((next, dists));
            }
            depth += 1;
            next = info.parent;
        }
    }

    #[must_use]
    pub fn get_root_and_path(&mut self, dest: PublicKey) -> (PublicKey, Vec<PeerPort>) {
        if let Some(cached) = self.cache.get(&dest) {
            return (cached.root, cached.path.clone());
        }
        let mut ports = Vec::new();
        let mut visited = HashSet::new();
        let mut next = dest;
        loop {
            if !visited.insert(next) {
                return (dest, Vec::new());
            }
            let Some(info) = self.infos.get(&next) else {
                return (dest, Vec::new());
            };
            if next == info.parent {
                break;
            }
            ports.push(info.res.port);
            next = info.parent;
        }
        let root = next;
        ports.reverse();
        self.cache.insert(
            dest,
            RouterPath {
                root,
                path: ports.clone(),
            },
        );
        (root, ports)
    }

    #[must_use]
    pub fn get_dist(&mut self, dest_path: &[PeerPort], key: PublicKey) -> u64 {
        let (root, key_path) = self.get_root_and_path(key);
        match self.infos.get(&root) {
            Some(info) if info.parent == root => {}
            _ => return u64::MAX,
        }
        let self_key = *self.crypto.public_key();
        let (self_root, _) = self.get_root_and_path(self_key);
        if root != self_root {
            return u64::MAX;
        }
        let end = dest_path.len().min(key_path.len());
        let mut common = 0;
        for i in 0..end {
            if key_path[i] == dest_path[i] {
                common += 1;
            } else {
                break;
            }
        }
        (key_path.len() + dest_path.len() - 2 * common) as u64
    }

    #[must_use]
    pub fn get_ancestry(&self, key: PublicKey) -> Vec<PublicKey> {
        let mut anc = Vec::with_capacity(32);
        self.backwards_ancestry(&mut anc, key);
        anc.reverse();
        anc
    }

    fn backwards_ancestry(&self, anc: &mut Vec<PublicKey>, mut key: PublicKey) {
        loop {
            if anc.contains(&key) {
                return;
            }
            match self.infos.get(&key) {
                Some(info) => {
                    anc.push(key);
                    key = info.parent;
                }
                None => return,
            }
        }
    }

    // ────────────── lookup ──────────────

    #[must_use]
    pub fn lookup(
        &mut self,
        path: &[PeerPort],
        watermark: Option<&mut u64>,
    ) -> Option<Arc<dyn PeerHandle>> {
        let self_key = *self.crypto.public_key();
        let self_dist = self.get_dist(path, self_key);

        let mut bound = u64::MAX;
        if let Some(w) = watermark {
            if self_dist < *w {
                bound = self_dist;
                *w = self_dist;
            } else {
                return None;
            }
        }

        let peer_keys: Vec<PublicKey> = self.peers.keys().copied().collect();
        let mut candidates: Vec<Candidate> = Vec::new();
        for k in &peer_keys {
            let dist = self.get_dist(path, *k);
            if dist >= bound {
                continue;
            }
            if let Some(entries) = self.peers.get(k) {
                for e in entries {
                    let pid = arc_identity(&e.handle);
                    let lag = self
                        .lags
                        .get(&pid)
                        .copied()
                        .unwrap_or(ROUTER_UNKNOWN_LATENCY);
                    let cost = u64::try_from(lag.as_millis()).unwrap_or(u64::MAX).max(1);
                    candidates.push(Candidate {
                        key: *k,
                        handle: Arc::clone(&e.handle),
                        dist,
                        cost,
                        prio: e.handle.prio(),
                        order: e.handle.order(),
                    });
                }
            }
        }

        let mut best: Option<Candidate> = None;
        let mut best_cost = u64::MAX;
        let mut best_dist = u64::MAX;

        for c in candidates {
            let replace = match &best {
                None => true,
                Some(b) => {
                    if c.key == b.key && c.prio < b.prio {
                        true
                    } else if c.key == b.key && c.prio > b.prio {
                        false
                    } else {
                        let lhs = c.cost.saturating_mul(c.dist);
                        let rhs = best_cost.saturating_mul(best_dist);
                        match lhs.cmp(&rhs) {
                            Ordering::Less => true,
                            Ordering::Greater => false,
                            Ordering::Equal => match c.dist.cmp(&best_dist) {
                                Ordering::Less => true,
                                Ordering::Greater => false,
                                Ordering::Equal => match c.cost.cmp(&best_cost) {
                                    Ordering::Less => true,
                                    Ordering::Greater => false,
                                    Ordering::Equal => c.order < b.order,
                                },
                            },
                        }
                    }
                }
            };
            if replace {
                best_cost = c.cost;
                best_dist = c.dist;
                best = Some(c);
            }
        }

        best.map(|c| c.handle)
    }
    fn fix_blooms_on_tree(&mut self) {
        let self_key = *self.crypto.public_key();
        let Some(self_info) = self.infos.get(&self_key) else {
            return;
        };
        let self_parent = self_info.parent;
        let keys: Vec<PublicKey> = self.blooms.iter().map(|(k, _)| *k).collect();
        for pk in keys {
            let was_on = self
                .blooms
                .iter()
                .find(|(k, _)| **k == pk)
                .is_some_and(|(_, i)| i.on_tree);
            let is_on =
                self_parent == pk || self.infos.get(&pk).is_some_and(|i| i.parent == self_key);
            if let Some(info) = self.blooms.get_mut(&pk) {
                info.on_tree = is_on;
                if was_on && !is_on {
                    info.send = Bloom::new();
                }
            }
            if was_on && !is_on {
                let peers: Vec<Arc<dyn PeerHandle>> = self
                    .peers
                    .get(&pk)
                    .map_or_default(|v| v.iter().map(|e| Arc::clone(&e.handle)).collect());
                let blank = Bloom::new();
                for p in peers {
                    p.send_bloom(&blank);
                }
            }
        }
    }

    fn compute_bloom_for(&mut self, key: PublicKey, keep_ones: bool) -> (Bloom, bool) {
        let self_key = *self.crypto.public_key();
        let xform = (self.config.bloom_transform)(&self_key);

        let mut b = Bloom::new();
        b.add_bytes(&xform);

        let others: Vec<Bloom> = self
            .blooms
            .iter()
            .filter(|(k, info)| info.on_tree && **k != key)
            .map(|(_, info)| info.recv.clone())
            .collect();
        for other in &others {
            b.merge(other);
        }

        let Some(info) = self.blooms.get_mut(&key) else {
            return (b, true);
        };

        if keep_ones {
            if !info.z_dirty {
                let probe = {
                    let mut p = b.clone();
                    p.merge(&info.send);
                    p
                };
                if probe != b {
                    info.z_dirty = true;
                }
            }
            b.merge(&info.send);
        } else {
            info.z_dirty = false;
        }

        let is_new = b != info.send;
        if is_new {
            info.send = b.clone();
        } else {
            b = info.send.clone();
        }
        (b, is_new)
    }

    fn send_all_blooms(&mut self) {
        let keys: Vec<PublicKey> = self
            .blooms
            .iter()
            .filter(|(_, i)| i.on_tree)
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            let keep_ones = self
                .blooms
                .iter()
                .find(|(kk, _)| **kk == k)
                .is_some_and(|(_, i)| !i.z_dirty);
            let (b, is_new) = self.compute_bloom_for(k, keep_ones);
            let Some(info) = self.blooms.get_mut(&k) else {
                continue;
            };
            info.seq = info.seq.wrapping_add(1);
            let should_send = is_new || info.seq >= 3600;
            if should_send {
                info.seq = 0;
            }
            if should_send {
                let peers: Vec<Arc<dyn PeerHandle>> = self
                    .peers
                    .get(&k)
                    .map_or_default(|v| v.iter().map(|e| Arc::clone(&e.handle)).collect());
                for p in peers {
                    p.send_bloom(&b);
                }
            }
        }
    }

    /// Периодическое обслуживание. В Go это `_doMaintenance`; у нас пока
    /// только Bloom'ы — `_fix`/`_sendAnnounces` придут со следующим этапом.
    pub fn do_maintenance(&mut self) {
        self.fix_blooms_on_tree();
        self.send_all_blooms();
    }
}
