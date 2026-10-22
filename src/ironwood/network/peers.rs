use std::collections::HashMap;
use std::sync::Arc;

use crate::ironwood::network::{PeerHandle, crypto::PublicKey, peer::Peer, wire::PeerPort};

/// Реестр активных пиров. Один ключ может держать несколько сессий.
pub struct Peers {
    by_key: HashMap<PublicKey, Vec<Arc<Peer>>>,
    ports: HashMap<PeerPort, PublicKey>,
    next_port: PeerPort,
    order: u64,
}

impl Peers {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            ports: HashMap::new(),
            next_port: 0,
            order: 0,
        }
    }

    /// Порт для нового соединения к `key`: переиспользует существующий
    /// или аллоцирует новый (пропуская 0).
    pub fn port_for(&mut self, key: &PublicKey) -> PeerPort {
        if let Some(ps) = self.by_key.get(key)
            && let Some(p) = ps.first()
        {
            return p.port;
        }
        loop {
            self.next_port = self.next_port.wrapping_add(1);
            if self.next_port == 0 {
                continue;
            }
            if !self.ports.contains_key(&self.next_port) {
                self.ports.insert(self.next_port, *key);
                return self.next_port;
            }
        }
    }

    /// `order` для нового пира — монотонно растёт.
    pub const fn allocate_order(&mut self) -> u64 {
        let o = self.order;
        self.order = self.order.wrapping_add(1);
        o
    }

    /// Добавить пира. `true` если ключ был новым.
    pub fn add(&mut self, peer: Arc<Peer>) -> bool {
        let key = peer.key();
        let is_new_key = !self.by_key.contains_key(&key);
        self.by_key.entry(key).or_default().push(peer);
        is_new_key
    }

    /// Удалить конкретный `Arc<Peer>` (по указателю).
    pub fn remove(&mut self, peer: &Arc<Peer>) -> bool {
        let key = peer.key();
        let Some(list) = self.by_key.get_mut(&key) else {
            return false;
        };
        let before = list.len();
        list.retain(|p| !Arc::ptr_eq(p, peer));
        let removed = list.len() < before;
        if list.is_empty() {
            self.by_key.remove(&key);
            self.ports.remove(&peer.port);
        }
        removed
    }

    #[must_use]
    pub fn get(&self, key: &PublicKey) -> &[Arc<Peer>] {
        self.by_key.get(key).map_or(&[], Vec::as_slice)
    }

    pub fn iter_all(&self) -> impl Iterator<Item = &Arc<Peer>> {
        self.by_key.values().flatten()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

impl Default for Peers {
    fn default() -> Self {
        Self::new()
    }
}
