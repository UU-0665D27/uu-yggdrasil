//! Wire-сообщения pathfinder'а: `PathLookup`, PathNotify(+Info), `PathBroken`.
//! Формат Go-совместим. Сами алгоритмы pathfinder'а появятся позже,
//! поверх `Router`.

use crate::ironwood::{
    errors::Error,
    network::{
        config::Config,
        crypto::{Crypto, PublicKey, SIGNATURE_SIZE, Signature, public_key_verify},
        peer::PeerHandle,
        router::Router,
        traffic::Traffic,
        wire::{
            PeerPort, WireEncodable, WirePacketType, wire_append_path, wire_append_uint,
            wire_chop_path, wire_chop_slice, wire_chop_uint, wire_size_path, wire_size_uint,
        },
    },
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::HashMap,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// `pathLookup { source, dest, from }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLookup {
    pub source: PublicKey,
    /// Может быть полным или частичным ключом (из IPv6-адреса).
    pub dest: [u8; 32],
    pub from: Vec<PeerPort>,
}

impl PathLookup {
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut from = Vec::new();
        if !wire_chop_path(&mut from, &mut rest) {
            return Err(Error::DECODE);
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(Self {
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest,
            from,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathLookup
    }
}

impl WireEncodable for PathLookup {
    fn size(&self) -> usize {
        32 + 32 + wire_size_path(&self.from)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(&self.dest);
        wire_append_path(out, &self.from);
        Ok(())
    }
}

/// `pathNotifyInfo { seq, path, sig }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotifyInfo {
    pub seq: u64,
    pub path: Vec<PeerPort>,
    pub sig: Signature,
}

impl PathNotifyInfo {
    /// `seq(varint) || path || sig` — то, что подписывает `source`.
    #[must_use]
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + wire_size_path(&self.path));
        wire_append_uint(&mut out, self.seq);
        wire_append_path(&mut out, &self.path);
        out
    }

    /// `func (info *pathNotifyInfo) equal(cmp)` — сравнить `seq` и `path`,
    /// игнорируя `sig`.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.seq == other.seq && self.path == other.path
    }

    /// Читает info из потока, оставляя хвост в `data`.
    ///
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn chop(data: &mut &[u8]) -> Result<Self, Error> {
        let seq = wire_chop_uint(data).ok_or(Error::DECODE)?;
        let mut path = Vec::new();
        if !wire_chop_path(&mut path, data) {
            return Err(Error::DECODE);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !wire_chop_slice(&mut sig_bytes, data) {
            return Err(Error::DECODE);
        }
        Ok(Self {
            seq,
            path,
            sig: Signature::from_bytes(&sig_bytes),
        })
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке байт или непустом остатке.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let info = Self::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(info)
    }
}

impl WireEncodable for PathNotifyInfo {
    fn size(&self) -> usize {
        wire_size_uint(self.seq) + wire_size_path(&self.path) + SIGNATURE_SIZE
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_uint(out, self.seq);
        wire_append_path(out, &self.path);
        out.extend_from_slice(&self.sig.to_bytes());
        Ok(())
    }
}

/// `pathNotify { path, watermark, source, dest, info }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotify {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub info: PathNotifyInfo,
}

impl PathNotify {
    /// `func (notify *pathNotify) check()`.
    #[must_use]
    pub fn check(&self) -> bool {
        public_key_verify(&self.source, &self.info.bytes_for_sig(), &self.info.sig)
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;

        let mut path = Vec::new();
        if !wire_chop_path(&mut path, &mut rest) {
            return Err(Error::DECODE);
        }
        let watermark = wire_chop_uint(&mut rest).ok_or(Error::DECODE)?;

        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }

        let info = PathNotifyInfo::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }

        Ok(Self {
            path,
            watermark,
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest: PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?,
            info,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathNotify
    }
}

impl WireEncodable for PathNotify {
    fn size(&self) -> usize {
        wire_size_path(&self.path)
            + wire_size_uint(self.watermark)
            + 32
            + 32
            + WireEncodable::size(&self.info)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_path(out, &self.path);
        wire_append_uint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        self.info.encode(out)
    }
}

/// `pathBroken { path, watermark, source, dest }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBroken {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
}

impl PathBroken {
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let mut path = Vec::new();
        if !wire_chop_path(&mut path, &mut rest) {
            return Err(Error::DECODE);
        }
        let watermark = wire_chop_uint(&mut rest).ok_or(Error::DECODE)?;
        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(Self {
            path,
            watermark,
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest: PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathBroken
    }
}

impl WireEncodable for PathBroken {
    fn size(&self) -> usize {
        wire_size_path(&self.path) + wire_size_uint(self.watermark) + 32 + 32
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_path(out, &self.path);
        wire_append_uint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        Ok(())
    }
}

impl PathNotifyInfo {
    /// Подписать `bytes_for_sig()` ключом `source`.
    pub fn sign(&mut self, key: &SigningKey) {
        self.sig = key.sign(&self.bytes_for_sig());
    }
}

/// Одна известная запись пути.
struct PathInfo {
    path: Vec<PeerPort>,
    seq: u64,
    req_time: Instant,
    last_seen: Instant,
    broken: bool,
}

/// Отложенный трафик + throttle-состояние для ещё-не-найденного `dest`.
struct PathRumor {
    traffic: Option<Traffic>,
    send_time: Instant,
    last_seen: Instant,
}
/// `func(*pathLookup)` — отладочный логгер lookup'ов.
pub type PathLookupLogger = Box<dyn Fn(&PathLookup) + Send + Sync>;
/// `pathfinder` из `pathfinder.go`.
pub struct Pathfinder {
    info: PathNotifyInfo,
    paths: HashMap<crate::ironwood::network::crypto::PublicKey, PathInfo>,
    rumors: HashMap<[u8; 32], PathRumor>,
    logger: Option<PathLookupLogger>,
}

impl Pathfinder {
    /// # Errors
    /// Не паникует.
    #[must_use]
    pub fn new(crypto: &Crypto) -> Self {
        let mut info = PathNotifyInfo {
            seq: 0,
            path: Vec::new(),
            sig: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        };
        info.sign(crypto.private_key());
        Self {
            info,
            paths: HashMap::new(),
            rumors: HashMap::new(),
            logger: None,
        }
    }

    pub fn set_logger<F>(&mut self, f: F)
    where
        F: Fn(&PathLookup) + Send + Sync + 'static,
    {
        self.logger = Some(Box::new(f));
    }

    /// # Errors
    /// Не паникует.
    #[must_use]
    pub const fn info(&self) -> &PathNotifyInfo {
        &self.info
    }

    #[must_use]
    pub fn has_path(&self, key: &crate::ironwood::network::crypto::PublicKey) -> bool {
        self.paths.contains_key(key)
    }

    // ────────────── lookup: отправка / обработка ──────────────

    /// Инициировать lookup для `dest` (throttled).
    pub fn send_lookup(&mut self, router: &mut Router, dest: [u8; 32]) {
        if let Ok(full) = PublicKey::from_bytes(&dest)
            && let Some(info) = self.paths.get_mut(&full)
        {
            if info.req_time.elapsed() < router.config().path_throttle {
                return;
            }
            info.req_time = Instant::now();
        }
        // Lookup может быть инициирован не трафиком, а запросом адреса
        // (`TUN`/`tcp()`): без rumor'а ответный notify будет отброшен.
        let xform = router.x_key(&dest);
        self.rumors.entry(xform).or_insert_with(|| PathRumor {
            traffic: None,
            send_time: Instant::now(),
            last_seen: Instant::now(),
        });
        let self_key = *router.crypto().public_key();
        let (_, from) = router.get_root_and_path(self_key);
        let lookup = PathLookup {
            source: self_key,
            dest,
            from,
        };
        self.handle_lookup_inner(router, self_key, &lookup);
    }

    /// Публичный handle — вызывается `Ironwood`-диспетчером по входящему `PathLookup`.
    pub fn handle_lookup(
        &mut self,
        router: &mut Router,
        from_peer: &dyn PeerHandle,
        lookup: &PathLookup,
    ) {
        if !router.blooms().on_tree(&from_peer.key()) {
            return;
        }
        self.handle_lookup_inner(router, from_peer.key(), lookup);
    }

    fn handle_lookup_inner(
        &mut self,
        router: &mut Router,
        from_key: crate::ironwood::network::crypto::PublicKey,
        lookup: &PathLookup,
    ) {
        if let Some(logger) = &self.logger {
            logger(lookup);
        }
        Self::send_multicast_lookup(router, from_key, lookup);

        let dx = router.x_key(&lookup.dest);
        let sx = router.x_key(router.crypto().public_key().as_bytes());
        if dx != sx {
            return;
        }
        // Мы — target. Отправляем notify обратно по `lookup.from`.
        let self_key = *router.crypto().public_key();
        let (_, path) = router.get_root_and_path(self_key);
        let mut notify_info = PathNotifyInfo {
            seq: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            path,
            sig: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        };
        if self.info.equal(&notify_info) {
            notify_info = self.info.clone();
        } else {
            notify_info.sign(router.crypto().private_key());
            self.info = notify_info.clone();
        }

        let notify = PathNotify {
            path: lookup.from.clone(),
            watermark: u64::MAX,
            source: self_key,
            dest: lookup.source,
            info: notify_info,
        };
        self.handle_notify_inner(router, notify.source, &notify);
    }

    fn send_multicast_lookup(
        router: &Router,
        from_key: crate::ironwood::network::crypto::PublicKey,
        lookup: &PathLookup,
    ) {
        let xform = router.x_key(&lookup.dest);
        let keys: Vec<crate::ironwood::network::crypto::PublicKey> =
            router.blooms().iter().map(|(k, _)| *k).collect();
        for pk in keys {
            let Some(info) = router
                .blooms()
                .iter()
                .find(|(k, _)| **k == pk)
                .map(|(_, i)| i)
            else {
                continue;
            };
            if !info.on_tree || pk == from_key {
                continue;
            }
            if !info.recv.test(&xform) {
                continue;
            }
            if let Some(peer) = router.best_peer_for(&pk) {
                peer.send_path_lookup(lookup);
            }
        }
    }

    // ────────────── notify ──────────────

    pub fn handle_notify(
        &mut self,
        router: &mut Router,
        from_peer: &dyn PeerHandle,
        notify: &PathNotify,
    ) {
        self.handle_notify_inner(router, from_peer.key(), notify);
    }

    fn handle_notify_inner(
        &mut self,
        router: &mut Router,
        _from_key: crate::ironwood::network::crypto::PublicKey,
        notify: &PathNotify,
    ) {
        // Forward, если мы не target.
        let mut wm = notify.watermark;
        let next = router.lookup(&notify.path, Some(&mut wm));
        if let Some(p) = next {
            let mut fwd = notify.clone();
            fwd.watermark = wm;
            p.send_path_notify(&fwd);
            return;
        }

        if notify.dest != *router.crypto().public_key() {
            return;
        }

        let source = notify.source;

        // Уже есть запись?
        if let Some(existing) = self.paths.get(&source) {
            if notify.info.seq <= existing.seq {
                return;
            }
            let mut probe = notify.info.clone();
            probe.path.clone_from(&existing.path);
            if probe.equal(&notify.info) {
                return;
            }
        } else {
            let xform = router.x_key(source.as_bytes());
            if !self.rumors.contains_key(&xform) {
                return;
            }
        }
        if !notify.check() {
            return;
        }

        // Обновить или создать запись.
        let mut traffic_to_deliver: Option<Traffic> = None;
        if let Some(mut info) = self.paths.remove(&source) {
            info.path.clone_from(&notify.info.path);
            info.seq = notify.info.seq;
            info.broken = false;
            info.last_seen = Instant::now();
            self.paths.insert(source, info);
        } else {
            let xform = router.x_key(source.as_bytes());
            if let Some(rumor) = self.rumors.remove(&xform)
                && let Some(tr) = rumor.traffic
                && tr.dest == source
            {
                traffic_to_deliver = Some(tr);
            }
            self.paths.insert(
                source,
                PathInfo {
                    path: notify.info.path.clone(),
                    seq: notify.info.seq,
                    req_time: Instant::now(),
                    last_seen: Instant::now(),
                    broken: false,
                },
            );
        }

        (router.config().path_notify)(&source);

        if let Some(tr) = traffic_to_deliver {
            self.handle_traffic_and_dispatch(router, tr);
        }
    }

    // ────────────── broken ──────────────

    pub fn handle_broken(
        &mut self,
        router: &mut Router,
        _from_peer: &dyn PeerHandle,
        broken: &PathBroken,
    ) {
        self.handle_broken_inner(router, broken);
    }

    fn handle_broken_inner(&mut self, router: &mut Router, broken: &PathBroken) {
        let mut wm = broken.watermark;
        let next = router.lookup(&broken.path, Some(&mut wm));
        if let Some(p) = next {
            let mut fwd = broken.clone();
            fwd.watermark = wm;
            p.send_path_broken(&fwd);
            return;
        }

        if broken.source != *router.crypto().public_key() {
            return;
        }
        if let Some(info) = self.paths.get_mut(&broken.dest) {
            info.broken = true;
        }
        self.send_lookup(router, *broken.dest.as_bytes());
    }

    /// Сгенерировать `PathBroken` для потерянного трафика.
    pub fn do_broken(&mut self, router: &mut Router, tr: &Traffic) {
        let broken = PathBroken {
            path: tr.from.clone(),
            watermark: u64::MAX,
            source: tr.source,
            dest: tr.dest,
        };
        self.handle_broken_inner(router, &broken);
    }

    // ────────────── traffic / rumor ──────────────

    /// Инициировать lookup и запомнить трафик в `rumors[xform]` (throttled).
    pub fn rumor_send_lookup(
        &mut self,
        router: &mut Router,
        dest: crate::ironwood::network::crypto::PublicKey,
    ) {
        let xform = router.x_key(dest.as_bytes());
        if let Some(rumor) = self.rumors.get_mut(&xform) {
            if rumor.send_time.elapsed() < router.config().path_throttle {
                return;
            }
            rumor.send_time = Instant::now();
            rumor.last_seen = Instant::now();
        } else {
            self.rumors.insert(
                xform,
                PathRumor {
                    traffic: None,
                    send_time: Instant::now(),
                    last_seen: Instant::now(),
                },
            );
        }
        self.send_lookup(router, *dest.as_bytes());
    }

    /// Основной вход трафика: если путь известен — вернуть `Traffic` с
    /// заполненными `path`/`from` (для `Router::handle_traffic`);
    /// иначе — инициировать lookup и отложить в `rumors`, вернуть `None`.
    pub fn handle_traffic(&mut self, router: &mut Router, mut tr: Traffic) -> Option<Traffic> {
        if let Some(info) = self.paths.get_mut(&tr.dest) {
            tr.path.clone_from(&info.path);
            let self_key = *router.crypto().public_key();
            let (_, from) = router.get_root_and_path(self_key);
            tr.from = from;
            info.last_seen = Instant::now();
            return Some(tr);
        }
        self.rumor_send_lookup(router, tr.dest);
        let xform = router.x_key(tr.dest.as_bytes());
        if let Some(rumor) = self.rumors.get_mut(&xform) {
            rumor.traffic = Some(tr);
        }
        None
    }

    /// Внутренний helper — `handle_traffic` + `Router::handle_traffic` +
    /// диспетчеризация результата. Используется из `_handle_notify`,
    /// когда прорвался отложенный трафик.
    fn handle_traffic_and_dispatch(&mut self, router: &mut Router, tr: Traffic) {
        if let Some(tr) = self.handle_traffic(router, tr) {
            let action = router.handle_traffic(tr);
            match action {
                crate::ironwood::network::router::TrafficAction::Forward(p, tr) => {
                    p.send_traffic(tr);
                }
                crate::ironwood::network::router::TrafficAction::DeliverLocal(_) => {
                    // Ironwood сам разберётся в deliver; здесь просто
                    // маршрутизация завершена.
                }
                crate::ironwood::network::router::TrafficAction::Broken(tr) => {
                    self.do_broken(router, &tr);
                }
            }
        }
    }

    /// Обновить `last_seen` при получении трафика от `key`.
    pub fn reset_timeout(&mut self, key: &crate::ironwood::network::crypto::PublicKey) {
        if let Some(info) = self.paths.get_mut(key)
            && !info.broken
        {
            info.last_seen = Instant::now();
        }
    }

    /// Удалить просроченные `paths` и `rumors`.
    pub fn do_maintenance(&mut self, router: &mut Router, config: &Config) {
        let timeout = config.path_timeout;
        let now = Instant::now();
        self.paths
            .retain(|_, info| now.duration_since(info.last_seen) < timeout);
        self.rumors
            .retain(|_, rumor| now.duration_since(rumor.last_seen) < timeout);

        // Трафик мог прийти раньше, чем появились bloom'ы/координаты пиров.
        // Первый lookup в таком случае уходит в никуда; повторяем его, пока
        // маршрут не найдётся (не чаще `path_throttle`).
        let retry: Vec<([u8; 32], PublicKey)> = self
            .rumors
            .iter()
            .filter_map(|(xform, rumor)| {
                let tr = rumor.traffic.as_ref()?;
                (now.duration_since(rumor.send_time) >= config.path_throttle)
                    .then_some((*xform, tr.dest))
            })
            .collect();
        for (xform, dest) in retry {
            if let Some(rumor) = self.rumors.get_mut(&xform) {
                rumor.send_time = now;
                rumor.last_seen = now;
            }
            self.send_lookup(router, *dest.as_bytes());
        }
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn encode<T: WireEncodable>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out).expect("encode");
        assert_eq!(out.len(), WireEncodable::size(v));
        out
    }

    #[test]
    fn lookup_roundtrip() {
        let l = PathLookup {
            source: sk(1).verifying_key(),
            dest: *sk(2).verifying_key().as_bytes(),
            from: vec![1, 300, u64::MAX],
        };
        let out = encode(&l);
        assert_eq!(PathLookup::decode(&out).expect("decode"), l);
        for cut in 0..out.len() {
            assert!(PathLookup::decode(&out[..cut]).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn notify_info_roundtrip_and_sign() {
        let key = sk(3);
        let mut info = PathNotifyInfo {
            seq: 42,
            path: vec![1, 2, 3],
            sig: Signature::from_bytes(&[0u8; 64]),
        };
        info.sign(&key);
        assert!(public_key_verify(
            &key.verifying_key(),
            &info.bytes_for_sig(),
            &info.sig
        ));

        let out = encode(&info);
        assert_eq!(PathNotifyInfo::decode(&out).expect("decode"), info);
        for cut in 0..out.len() {
            assert!(PathNotifyInfo::decode(&out[..cut]).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn notify_roundtrip_and_check() {
        let key = sk(4);
        let mut info = PathNotifyInfo {
            seq: 9,
            path: vec![7],
            sig: Signature::from_bytes(&[0u8; 64]),
        };
        info.sign(&key);
        let n = PathNotify {
            path: vec![1, 2],
            watermark: u64::MAX,
            source: key.verifying_key(),
            dest: sk(5).verifying_key(),
            info,
        };
        assert!(n.check());
        let mut bad = n.clone();
        bad.info.seq += 1;
        assert!(!bad.check());

        let out = encode(&n);
        let got = PathNotify::decode(&out).expect("decode");
        assert_eq!(got, n);
        for cut in 0..out.len() {
            assert!(PathNotify::decode(&out[..cut]).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn broken_roundtrip() {
        let b = PathBroken {
            path: vec![1, 2, 3],
            watermark: 5,
            source: sk(6).verifying_key(),
            dest: sk(7).verifying_key(),
        };
        let out = encode(&b);
        assert_eq!(PathBroken::decode(&out).expect("decode"), b);
        for cut in 0..out.len() {
            assert!(PathBroken::decode(&out[..cut]).is_err(), "cut={cut}");
        }
    }
}
