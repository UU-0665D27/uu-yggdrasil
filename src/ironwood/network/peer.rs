//! `Peer` и `PeerHandle`. Framing (`[uvarint len][type][body]`),
//! dispatch входящих сообщений, sync- и async-циклы, `spawn_peer`.
//!
//! Очередь исходящих — `Mutex<VecDeque<OutFrame>>` + `Notify`. Это даёт
//! одну и ту же структуру для async-writer'а (в рантайме) и для
//! sync-цикла (`session_loop_sync`, для `handle_conn_sync`/фаззера).

use std::{
    collections::VecDeque,
    io::Read,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, sync::Notify};
use tokio_util::{io::SyncIoBridge, sync::CancellationToken};

use crate::ironwood::{
    errors::Error,
    network::{
        bloomfilter::Bloom,
        crypto::PublicKey,
        pathfinder::{PathBroken, PathLookup, PathNotify},
        router::types::{RouterAnnounce, RouterSigReq, RouterSigRes},
        traffic::Traffic,
        wire::{PeerPort, WireEncodable, WirePacketType, wire_append_uint, wire_chop_uint},
    },
    types::packetconn::{AsyncConn, ReadWrite},
};

/// Всё, что `Peer` может отправить.
/// Крупные варианты — за `Box`, чтобы размер enum был 16 байт, а не 1 КБ.
#[derive(Debug, Clone)]
pub enum OutFrame {
    KeepAlive,
    SigReq(RouterSigReq),
    SigRes(Box<RouterSigRes>),
    Announce(Box<RouterAnnounce>),
    Bloom(Box<Bloom>),
    PathLookup(Box<PathLookup>),
    PathNotify(Box<PathNotify>),
    PathBroken(Box<PathBroken>),
    Traffic(Box<Traffic>),
}

impl OutFrame {
    #[must_use]
    pub const fn wire_type(&self) -> WirePacketType {
        match self {
            Self::KeepAlive => WirePacketType::KeepAlive,
            Self::SigReq(_) => WirePacketType::ProtoSigReq,
            Self::SigRes(_) => WirePacketType::ProtoSigRes,
            Self::Announce(_) => WirePacketType::ProtoAnnounce,
            Self::Bloom(_) => WirePacketType::ProtoBloomFilter,
            Self::PathLookup(_) => WirePacketType::ProtoPathLookup,
            Self::PathNotify(_) => WirePacketType::ProtoPathNotify,
            Self::PathBroken(_) => WirePacketType::ProtoPathBroken,
            Self::Traffic(_) => WirePacketType::Traffic,
        }
    }

    /// Кодирует тело (без байта типа).
    ///
    /// # Errors
    /// Пробрасывает ошибки `encode` вложенных сообщений.
    pub fn encode_body(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            Self::KeepAlive => {}
            Self::SigReq(v) => v.encode(&mut out)?,
            Self::SigRes(v) => v.encode(&mut out)?,
            Self::Announce(v) => v.encode(&mut out)?,
            Self::Bloom(v) => v.encode(&mut out)?,
            Self::PathLookup(v) => v.encode(&mut out)?,
            Self::PathNotify(v) => v.encode(&mut out)?,
            Self::PathBroken(v) => v.encode(&mut out)?,
            Self::Traffic(v) => v.encode(&mut out)?,
        }
        Ok(out)
    }
}

/// Кодирует `OutFrame` в полный фрейм: `[uvarint len][type][body]`.
///
/// # Errors
/// [`Error::ENCODE`] при переполнении размера или ошибке вложенного `encode`.
pub fn encode_frame(frame: &OutFrame) -> Result<Vec<u8>, Error> {
    let body = frame.encode_body()?;
    let total = 1usize.checked_add(body.len()).ok_or(Error::ENCODE)?;
    let total = u64::try_from(total).map_err(|_| Error::ENCODE)?;
    let mut out = Vec::with_capacity(10 + body.len() + 1);
    wire_append_uint(&mut out, total);
    out.push(u8::from(frame.wire_type()));
    out.extend_from_slice(&body);
    Ok(out)
}

/// Всё, что нужно `Router`/`Pathfinder` от пира.
pub trait PeerHandle: Send + Sync {
    fn key(&self) -> PublicKey;
    fn port(&self) -> PeerPort;
    fn prio(&self) -> u8;
    fn order(&self) -> u64;

    fn send(&self, frame: OutFrame);

    fn send_sig_req(&self, req: &RouterSigReq) {
        self.send(OutFrame::SigReq(*req));
    }
    fn send_sig_res(&self, res: &RouterSigRes) {
        self.send(OutFrame::SigRes(Box::new(*res)));
    }
    fn send_announce(&self, ann: &RouterAnnounce) {
        self.send(OutFrame::Announce(Box::new(*ann)));
    }
    fn send_bloom(&self, b: &Bloom) {
        self.send(OutFrame::Bloom(Box::new(b.clone())));
    }
    fn send_path_lookup(&self, l: &PathLookup) {
        self.send(OutFrame::PathLookup(Box::new(l.clone())));
    }
    fn send_path_notify(&self, n: &PathNotify) {
        self.send(OutFrame::PathNotify(Box::new(n.clone())));
    }
    fn send_path_broken(&self, b: &PathBroken) {
        self.send(OutFrame::PathBroken(Box::new(b.clone())));
    }
    fn send_traffic(&self, tr: Traffic) {
        self.send(OutFrame::Traffic(Box::new(tr)));
    }
}

/// Peer — handle пира. Send-queue общая для async-writer и sync-loop.
pub struct Peer {
    pub key: PublicKey,
    pub port: PeerPort,
    pub prio: u8,
    pub order: u64,
    send_queue: Mutex<VecDeque<OutFrame>>,
    notify: Notify,
}

impl Peer {
    #[must_use]
    pub fn new(key: PublicKey, port: PeerPort, prio: u8, order: u64) -> Self {
        Self {
            key,
            port,
            prio,
            order,
            send_queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<OutFrame>> {
        self.send_queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Вынуть один фрейм из очереди (writer/sync-loop).
    fn try_pop(&self) -> Option<OutFrame> {
        self.lock_queue().pop_front()
    }

    /// Doc-hidden — используется fuzz-таргетом.
    #[doc(hidden)]
    pub fn fuzz_take_send(&self) -> Option<OutFrame> {
        self.try_pop()
    }
}

impl PeerHandle for Peer {
    fn key(&self) -> PublicKey {
        self.key
    }
    fn port(&self) -> PeerPort {
        self.port
    }
    fn prio(&self) -> u8 {
        self.prio
    }
    fn order(&self) -> u64 {
        self.order
    }
    fn send(&self, frame: OutFrame) {
        self.lock_queue().push_back(frame);
        self.notify.notify_one();
    }
}

/// Разобранное входящее сообщение.
#[derive(Debug)]
pub enum InFrame {
    KeepAlive,
    SigReq(RouterSigReq),
    SigRes(Box<RouterSigRes>),
    Announce(Box<RouterAnnounce>),
    Bloom(Box<Bloom>),
    PathLookup(Box<PathLookup>),
    PathNotify(Box<PathNotify>),
    PathBroken(Box<PathBroken>),
    Traffic(Box<Traffic>),
}

/// `PacketDispatcher` — обработчик пришедших фреймов.
/// `Send` — чтобы `dyn PacketDispatcher` можно было тащить в `spawn_blocking`.
pub trait PacketDispatcher: Send {
    /// # Errors
    /// Пробрасывает ошибку обработки. Соединение будет закрыто.
    fn dispatch(&mut self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error>;
}

/// Читает один `[len][type][body]` из `r`. `Ok(None)` — чистый EOF.
///
/// # Errors
/// См. `session_loop`.
fn decode_one_frame(r: &mut dyn Read, max_frame: u64) -> Result<Option<InFrame>, Error> {
    // Varint длины, по одному байту.
    let mut len_buf = [0u8; 10];
    let mut len_bytes = 0usize;
    for (i, slot) in len_buf.iter_mut().enumerate() {
        let mut b = [0u8; 1];
        match r.read_exact(&mut b) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => return Err(Error::ENCODE),
        }
        *slot = b[0];
        len_bytes = i + 1;
        if b[0] < 0x80 {
            break;
        }
    }
    if len_bytes == 0 {
        return Err(Error::DECODE);
    }

    let mut slice = &len_buf[..len_bytes];
    let frame_len = wire_chop_uint(&mut slice).ok_or(Error::DECODE)?;
    if frame_len > max_frame {
        return Err(Error::OVERSIZED_MESSAGE);
    }
    let frame_len = usize::try_from(frame_len).map_err(|_| Error::OVERSIZED_MESSAGE)?;
    if frame_len == 0 {
        return Err(Error::EMPTY_MESSAGE);
    }

    let mut frame = vec![0u8; frame_len];
    r.read_exact(&mut frame).map_err(|_| Error::ENCODE)?;

    let ptype_byte = frame[0];
    let body = &frame[1..];
    let ptype = WirePacketType::try_from_byte(ptype_byte)?;

    let iframe = match ptype {
        WirePacketType::Dummy | WirePacketType::KeepAlive => InFrame::KeepAlive,
        WirePacketType::ProtoSigReq => InFrame::SigReq(RouterSigReq::decode(body)?),
        WirePacketType::ProtoSigRes => InFrame::SigRes(Box::new(RouterSigRes::decode(body)?)),
        WirePacketType::ProtoAnnounce => InFrame::Announce(Box::new(RouterAnnounce::decode(body)?)),
        WirePacketType::ProtoBloomFilter => InFrame::Bloom(Box::new(Bloom::decode(body)?)),
        WirePacketType::ProtoPathLookup => InFrame::PathLookup(Box::new(PathLookup::decode(body)?)),
        WirePacketType::ProtoPathNotify => InFrame::PathNotify(Box::new(PathNotify::decode(body)?)),
        WirePacketType::ProtoPathBroken => InFrame::PathBroken(Box::new(PathBroken::decode(body)?)),
        WirePacketType::Traffic => InFrame::Traffic(Box::new(Traffic::decode(body)?)),
    };
    Ok(Some(iframe))
}

/// Read-only цикл: читает фреймы, зовёт dispatcher. Отправка — только через
/// `Peer::send` → очередь → внешний writer (`spawn_peer`) или `session_loop_sync`.
///
/// # Errors
/// См. `decode_one_frame`.
pub fn session_loop(
    peer: &dyn PeerHandle,
    conn: &mut dyn Read,
    dispatcher: &mut dyn PacketDispatcher,
    max_frame: u64,
) -> Result<(), Error> {
    loop {
        let Some(frame) = decode_one_frame(conn, max_frame)? else {
            return Ok(());
        };
        dispatcher.dispatch(peer, frame)?;
    }
}

/// Синхронный цикл для `handle_conn_sync`: чтение + слив `send_queue` в `conn`.
/// Один поток, без tokio. `dispatcher.dispatch` может класть `OutFrame`
/// в очередь через `peer.send` — сливаются перед следующим чтением.
///
/// # Errors
/// См. `decode_one_frame` + [`Error::ENCODE`] на запись.
pub fn session_loop_sync(
    peer: &Peer,
    conn: &mut dyn ReadWrite,
    dispatcher: &mut dyn PacketDispatcher,
    max_frame: u64,
) -> Result<(), Error> {
    loop {
        // Слить отправленное.
        while let Some(frame) = peer.try_pop() {
            let bytes = encode_frame(&frame)?;
            conn.write_all(&bytes).map_err(|_| Error::ENCODE)?;
        }
        // Прочитать следующий фрейм.
        let Some(frame) = decode_one_frame(conn, max_frame)? else {
            // EOF: последняя best-effort попытка слить хвост.
            while let Some(frame) = peer.try_pop() {
                if let Ok(bytes) = encode_frame(&frame) {
                    let _ = conn.write_all(&bytes);
                }
            }
            return Ok(());
        };
        dispatcher.dispatch(peer, frame)?;
    }
}
type SplitConn = (
    tokio::io::ReadHalf<Box<dyn AsyncConn>>,
    tokio::io::WriteHalf<Box<dyn AsyncConn>>,
);
// ────────────────────────────────────────────────────────────────────
// Async spawn: reader + writer + keepalive + супервизор.
// ────────────────────────────────────────────────────────────────────

/// Запускает сессию поверх `conn`. Возвращает handle + `JoinHandle`,
/// который завершится, когда сессия закончится (EOF, ошибка, shutdown).
///
/// `external_shutdown` — родительский токен (например, от `PacketConn::close`).
/// Внутри создаётся дочерний; смерть любой из трёх задач отменяет дочерний.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn spawn_peer(
    key: PublicKey,
    port: PeerPort,
    prio: u8,
    order: u64,
    conn: Box<dyn AsyncConn>,
    dispatcher: Box<dyn PacketDispatcher + 'static>,
    max_frame: u64,
    keepalive_interval: Duration,
    external_shutdown: &CancellationToken,
) -> (Arc<Peer>, tokio::task::JoinHandle<()>) {
    let peer = Arc::new(Peer::new(key, port, prio, order));
    let shutdown = external_shutdown.child_token();

    let (read_half, write_half): SplitConn = tokio::io::split(conn);

    let mut set = tokio::task::JoinSet::new();

    // Writer: дренит очередь, пишет в сокет.
    {
        let peer_w = Arc::clone(&peer);
        let shutdown_w = shutdown.clone();
        set.spawn(async move {
            let mut wh = write_half;
            loop {
                while let Some(frame) = peer_w.try_pop() {
                    let bytes = match encode_frame(&frame) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            continue;
                        }
                    };
                    if wh.write_all(&bytes).await.is_err() {
                        shutdown_w.cancel();
                        return;
                    }
                }
                // notify_one хранит permit, если нет ждущих,
                // поэтому гонки между try_pop и notified().await нет.
                tokio::select! {
                    biased;
                    () = shutdown_w.cancelled() => return,
                    () = peer_w.notify.notified() => {}
                }
            }
        });
    }

    // Reader: sync-цикл в spawn_blocking через SyncIoBridge.
    {
        let peer_r = Arc::clone(&peer);
        let shutdown_r = shutdown.clone();
        set.spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let mut bridge = SyncIoBridge::new(read_half);
                let mut dispatcher = dispatcher;
                let _ = session_loop(peer_r.as_ref(), &mut bridge, dispatcher.as_mut(), max_frame);
            })
            .await;
            shutdown_r.cancel();
        });
    }

    // Keepalive: шлём `KeepAlive` при простое.
    {
        let peer_k = Arc::clone(&peer);
        let shutdown_k = shutdown.clone();
        set.spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // первый тик immediate — съедаем
            loop {
                tokio::select! {
                    biased;
                    () = shutdown_k.cancelled() => return,
                    _ = interval.tick() => {
                        peer_k.send(OutFrame::KeepAlive);
                    }
                }
            }
        });
    }

    // Supervisor: как только любая из задач завершилась, отменяем остальные.
    let handle = tokio::spawn(async move {
        if set.join_next().await.is_some() {
            shutdown.cancel();
        }
        while set.join_next().await.is_some() {}
    });

    (peer, handle)
}
