pub mod types;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer};

use crate::ironwood::network::{
    config::Config,
    crypto::{Crypto, PublicKey, public_key_less},
    wire::PeerPort,
};

pub use types::{RouterAnnounce, RouterInfo, RouterSigReq, RouterSigRes};

/// `routerPath { root, path }`.
#[derive(Debug, Clone)]
pub struct RouterPath {
    pub root: PublicKey,
    pub path: Vec<PeerPort>,
}

/// Per-peer metadata. Заполняется `Peer` при подключении.
#[derive(Debug, Clone, Copy)]
pub struct PeerMeta {
    pub prio: u8,
    pub order: u64,
    pub cost: u64,
}

/// `struct router` — состояние и чистые алгоритмы.
pub struct Router {
    crypto: Arc<Crypto>,
    config: Config,

    pub infos: HashMap<PublicKey, RouterInfo>,
    cache: HashMap<PublicKey, RouterPath>,
    peers: HashMap<PublicKey, Vec<PeerMeta>>,
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

    /// `func (r *router) _resetCache()`.
    pub fn reset_cache(&mut self) {
        self.cache.clear();
    }

    /// `func (r *router) _newReq()`.
    ///
    /// Ошибка `getrandom` намеренно игнорируется — как `crand.Read(nonce)`
    /// в Go. `nonce` здесь — только tie-breaker в `update()`, не крипто-назначение.
    /// При сбое OS RNG nonce = 0, что просто понижает приоритет анонса.
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

    /// `func (r *router) _becomeRoot()` — самоподписанный announce с port=0.
    pub fn become_root(&mut self) -> bool {
        let req = self.new_req();
        let self_key = *self.crypto.public_key();

        // Считаем подпись над `bytes_for_sig` — `psig` в структуре не участвует,
        // так что placeholder допустим.
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

    /// `func (r *router) _update(ann)` — принять/отклонить announce.
    ///
    /// Порядок проверок **обязан** совпадать на всех узлах; иначе пиры
    /// могут бесконечно спамить друг друга announce'ами.
    pub fn update(&mut self, ann: &RouterAnnounce) -> bool {
        if let Some(info) = self.infos.get(&ann.key) {
            match ann.res.req.seq.cmp(&info.res.req.seq) {
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => {
                    if public_key_less(&info.parent, &ann.parent) {
                        // info.parent < ann.parent — у нас (info) лучше (ниже),
                        // значит ann хуже → отклонить.
                        return false;
                    } else if public_key_less(&ann.parent, &info.parent) {
                        // ann.parent < info.parent — ann лучше, принять.
                    } else if ann.res.req.nonce < info.res.req.nonce {
                        // Тот же seq и parent, ann.nonce меньше — принять.
                    } else {
                        // Тот же seq и parent, nonce не лучше — отклонить.
                        return false;
                    }
                }
            }
        }

        self.cache.clear();

        let info = RouterInfo {
            parent: ann.parent,
            res: ann.res,
            sig: ann.sig,
        };
        let is_self = ann.key == *self.crypto.public_key();
        self.infos.insert(ann.key, info);

        if is_self {
            // TODO: refresh-таймер через config.router_refresh.
            self.refresh = true;
        } else {
            // TODO: timeout-таймер через config.router_timeout;
            // по истечении убрать ann.key из infos и очистить кэш.
        }
        true
    }

    /// `func (r *router) _getRootAndDists(dest)`.
    #[must_use]
    pub fn get_root_and_dists(
        &self,
        dest: PublicKey,
    ) -> Option<(PublicKey, HashMap<PublicKey, u64>)> {
        let mut dists = HashMap::new();
        let mut next = dest;
        let mut dist = 0u64;
        loop {
            if dists.contains_key(&next) {
                return None; // loop
            }
            let info = self.infos.get(&next)?;
            dists.insert(next, dist);
            if info.parent == next {
                return Some((next, dists));
            }
            dist += 1;
            next = info.parent;
        }
    }

    /// `func (r *router) _getRootAndPath(dest)` с кэшем.
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
                return (dest, Vec::new()); // loop
            }
            let Some(info) = self.infos.get(&next) else {
                return (dest, Vec::new()); // dead end
            };
            if next == info.parent {
                // Достигли корня — не пушим его port, `next` и есть root.
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

    /// `func (r *router) _getDist(destPath, key)`.
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

    /// `func (r *router) _getAncestry(key)` — от корня к `key`.
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

    pub fn add_peer(&mut self, key: PublicKey, meta: PeerMeta) {
        self.peers.entry(key).or_default().push(meta);
    }

    pub fn remove_peer(&mut self, key: &PublicKey) {
        self.peers.remove(key);
    }

    /// `func (r *router) _lookup(path, watermark)` — упрощённая версия.
    ///
    /// Возвращает ключ next-hop'а. Сортировка — по `cost * dist`, тай-брейк
    /// по меньшему `prio`, затем по меньшему `order` (старшие соединения).
    #[must_use]
    pub fn lookup(&mut self, path: &[PeerPort], watermark: Option<&mut u64>) -> Option<PublicKey> {
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
        let mut candidates: Vec<(PublicKey, PeerMeta, u64)> = Vec::new();
        for k in &peer_keys {
            let dist = self.get_dist(path, *k);
            if dist < bound {
                if let Some(metas) = self.peers.get(k) {
                    for &meta in metas {
                        candidates.push((*k, meta, dist));
                    }
                }
            }
        }

        let mut best: Option<(PublicKey, PeerMeta, u64)> = None;
        let mut best_cost = u64::MAX;
        let mut best_dist = u64::MAX;

        for &(key, meta, dist) in &candidates {
            let cost = meta.cost.max(1);
            let replace = match &best {
                None => true,
                Some((bk, bm, _)) => {
                    if key == *bk && meta.prio < bm.prio {
                        true
                    } else if key == *bk && meta.prio > bm.prio {
                        false
                    } else {
                        let lhs = cost.saturating_mul(dist);
                        let rhs = best_cost.saturating_mul(best_dist);
                        match lhs.cmp(&rhs) {
                            std::cmp::Ordering::Less => true,
                            std::cmp::Ordering::Greater => false,
                            std::cmp::Ordering::Equal => match dist.cmp(&best_dist) {
                                std::cmp::Ordering::Less => true,
                                std::cmp::Ordering::Greater => false,
                                std::cmp::Ordering::Equal => match cost.cmp(&best_cost) {
                                    std::cmp::Ordering::Less => true,
                                    std::cmp::Ordering::Greater => false,
                                    std::cmp::Ordering::Equal => meta.order < bm.order,
                                },
                            },
                        }
                    }
                }
            };
            if replace {
                best = Some((key, meta, dist));
                best_cost = cost;
                best_dist = dist;
            }
        }

        best.map(|(k, _, _)| k)
    }
}
