//! `Peer` и `PeerHandle`. Реализует framing (`[uvarint len][type][body]`)
//! и dispatch пришедших сообщений. Sync-ядро (`session_loop`) — для
//! фаззера и для reader-таска рантайма.

use tokio::sync::mpsc;

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
    types::packetconn::ReadWrite,
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

/// Аналог `pqPacket`: `Peer::send` кладёт в канал, а reader (sync) или
/// writer (async в рантайме) кодирует и шлёт в сокет.
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

/// Peer — handle пира. Содержит канал в writer, identity и stats.
pub struct Peer {
    pub key: PublicKey,
    pub port: PeerPort,
    pub prio: u8,
    pub order: u64,
    pub tx: mpsc::UnboundedSender<OutFrame>,
}

impl Peer {
    /// # Errors
    /// Не паникует. Всегда `Ok`.
    #[must_use]
    pub const fn new(
        key: PublicKey,
        port: PeerPort,
        prio: u8,
        order: u64,
        tx: mpsc::UnboundedSender<OutFrame>,
    ) -> Self {
        Self {
            key,
            port,
            prio,
            order,
            tx,
        }
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
        // Игнорируем: если writer упал, пир скоро отвалится по EOF.
        let _ = self.tx.send(frame);
    }
}

/// Разобранное входящее сообщение — то, что видит dispatcher.
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

/// Обработчик пришедших фреймов. Реализуется в `Router`/`Pathfinder`/
/// `PacketConn`; для фаззера — dummy.
pub trait PacketDispatcher {
    /// # Errors
    /// Пробрасывает ошибку обработки. Соединение будет закрыто.
    fn dispatch(&mut self, peer: &dyn PeerHandle, frame: InFrame) -> Result<(), Error>;
}

/// Sync reader-loop. Читает `[uvarint len][type][body]`, декодирует,
/// зовёт `dispatcher.dispatch`.
///
/// # Errors
/// - [`Error::OVERSIZED_MESSAGE`] при `frame_len > max_frame`;
/// - [`Error::EMPTY_MESSAGE`] при `frame_len == 0`;
/// - [`Error::DECODE`] при битом varint'е или невалидном type-байте;
/// - [`Error::UNRECOGNIZED_MESSAGE`] для type-байта вне диапазона;
/// - [`Error::ENCODE`] при I/O-ошибке чтения.
///
/// Возвращает `Ok(())` при чистом EOF (пир отключился).
pub fn session_loop(
    peer: &dyn PeerHandle,
    conn: &mut dyn ReadWrite,
    dispatcher: &mut dyn PacketDispatcher,
    max_frame: u64,
) -> Result<(), Error> {
    loop {
        let mut len_buf = [0u8; 10];
        let mut len_bytes = 0usize;
        for (i, slot) in len_buf.iter_mut().enumerate() {
            let mut b = [0u8; 1];
            match conn.read_exact(&mut b) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
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
        if conn.read_exact(&mut frame).is_err() {
            return Err(Error::ENCODE);
        }

        let ptype_byte = frame[0];
        let body = &frame[1..];
        let ptype = WirePacketType::try_from_byte(ptype_byte)?;

        let iframe = match ptype {
            WirePacketType::Dummy | WirePacketType::KeepAlive => InFrame::KeepAlive,
            WirePacketType::ProtoSigReq => InFrame::SigReq(RouterSigReq::decode(body)?),
            WirePacketType::ProtoSigRes => InFrame::SigRes(Box::new(RouterSigRes::decode(body)?)),
            WirePacketType::ProtoAnnounce => {
                InFrame::Announce(Box::new(RouterAnnounce::decode(body)?))
            }
            WirePacketType::ProtoBloomFilter => InFrame::Bloom(Box::new(Bloom::decode(body)?)),
            WirePacketType::ProtoPathLookup => {
                InFrame::PathLookup(Box::new(PathLookup::decode(body)?))
            }
            WirePacketType::ProtoPathNotify => {
                InFrame::PathNotify(Box::new(PathNotify::decode(body)?))
            }
            WirePacketType::ProtoPathBroken => {
                InFrame::PathBroken(Box::new(PathBroken::decode(body)?))
            }
            WirePacketType::Traffic => InFrame::Traffic(Box::new(Traffic::decode(body)?)),
        };

        dispatcher.dispatch(peer, iframe)?;
    }
}
