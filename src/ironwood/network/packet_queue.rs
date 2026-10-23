use crate::ironwood::network::{
    crypto::PublicKey,
    wire::{WireEncodable, WirePacketType},
};
use std::{collections::VecDeque, time::Instant};

/// `pqPacket` — общий интерфейс всех сообщений в очереди.
pub trait PqPacket: WireEncodable + Send {
    fn wire_type(&self) -> WirePacketType;
    fn source_key(&self) -> PublicKey;
    fn dest_key(&self) -> PublicKey;
}

struct PqPacketInfo {
    packet: Box<dyn PqPacket>,
    size: u64,
    time: Instant,
}

struct PqSource {
    key: PublicKey,
    infos: VecDeque<PqPacketInfo>,
    size: u64,
}

struct PqDest {
    key: PublicKey,
    sources: Vec<PqSource>,
    size: u64,
}

/// `packetQueue`: FIFO-очередь по (dest, source), плюс `drop_oldest` —
/// выкинуть самый старый пакет из самой длинной пары.
///
/// Инварианты:
/// - `self.size == Σ dest.size == ΣΣ source.size == ΣΣΣ info.size`.
/// - Если `dest.sources.is_empty()`, `dest` в `dests` не хранится.
/// - Если `source.infos.is_empty()`, `source` в `dest.sources` не хранится.
pub struct PacketQueue {
    dests: Vec<PqDest>,
    size: u64,
}

impl PacketQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dests: Vec::new(),
            size: 0,
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// `func (q *packetQueue) push(packet)`.
    pub fn push(&mut self, packet: Box<dyn PqPacket>) {
        let source_key = packet.source_key();
        let dest_key = packet.dest_key();
        let size = packet.size() as u64;
        let info = PqPacketInfo {
            packet,
            size,
            time: Instant::now(),
        };

        // Найти/создать dest.
        let dest = if let Some(i) = self.dests.iter().position(|d| d.key == dest_key) {
            &mut self.dests[i]
        } else {
            self.dests.push(PqDest {
                key: dest_key,
                sources: Vec::new(),
                size: 0,
            });
            // `last_mut` безопасен: только что запушили.
            if let Some(d) = self.dests.last_mut() {
                d
            } else {
                return;
            }
        };

        // Найти/создать source.
        let source = if let Some(i) = dest.sources.iter().position(|s| s.key == source_key) {
            &mut dest.sources[i]
        } else {
            dest.sources.push(PqSource {
                key: source_key,
                infos: VecDeque::new(),
                size: 0,
            });
            if let Some(s) = dest.sources.last_mut() {
                s
            } else {
                return;
            }
        };

        source.infos.push_back(info);
        source.size += size;
        dest.size += size;
        self.size += size;
    }

    /// `func (q *packetQueue) pop()` — самый старый пакет.
    pub fn pop(&mut self) -> Option<Box<dyn PqPacket>> {
        let (dest_idx, source_idx) = self.oldest_indices()?;
        let dest = &mut self.dests[dest_idx];
        let source = &mut dest.sources[source_idx];
        let info = source.infos.pop_front()?;

        source.size -= info.size;
        dest.size -= info.size;
        self.size -= info.size;

        if source.infos.is_empty() {
            dest.sources.remove(source_idx);
        }
        if dest.sources.is_empty() {
            self.dests.remove(dest_idx);
        }

        Some(info.packet)
    }

    /// `func (q *packetQueue) peek()`.
    #[must_use]
    pub fn peek(&self) -> Option<(&dyn PqPacket, u64)> {
        let (dest_idx, source_idx) = self.oldest_indices()?;
        let info = self.dests[dest_idx].sources[source_idx].infos.front()?;
        Some((info.packet.as_ref(), info.size))
    }

    /// Индексы `(dest, source)` с самым старым головным пакетом.
    /// В Go это делает heap по `infos[0].time`; при равенстве выбираем
    /// первый — как при стабильном обходе.
    fn oldest_indices(&self) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize, Instant)> = None;
        for (di, dest) in self.dests.iter().enumerate() {
            for (si, source) in dest.sources.iter().enumerate() {
                let Some(info) = source.infos.front() else {
                    continue;
                };
                if best.is_none_or(|(_, _, t)| info.time < t) {
                    best = Some((di, si, info.time));
                }
            }
        }
        best.map(|(di, si, _)| (di, si))
    }

    /// `func (q *packetQueue) drop()` — выкинуть самый старый пакет из самой
    /// длинной пары (dest → source). Возвращает `false` если очередь пуста.
    pub fn drop_oldest(&mut self) -> bool {
        if self.size == 0 {
            return false;
        }

        let mut dest_idx = 0;
        for (i, d) in self.dests.iter().enumerate().skip(1) {
            if d.size > self.dests[dest_idx].size {
                dest_idx = i;
            }
        }

        let dest = &mut self.dests[dest_idx];
        let mut source_idx = 0;
        for (i, s) in dest.sources.iter().enumerate().skip(1) {
            if s.size > dest.sources[source_idx].size {
                source_idx = i;
            }
        }

        let source = &mut dest.sources[source_idx];
        let Some(info) = source.infos.pop_front() else {
            return false;
        };

        source.size -= info.size;
        dest.size -= info.size;
        self.size -= info.size;

        if source.infos.is_empty() {
            dest.sources.remove(source_idx);
        }
        if dest.sources.is_empty() {
            self.dests.remove(dest_idx);
        }

        true
    }
}

impl Default for PacketQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PacketQueue {
    fn drop(&mut self) {
        // Без этого `Vec`-based очередь не освобождает `Vec<u8>` payload
        // до `Vec`-дропа. Явно чистим, чтобы фаззер не держал память.
        self.dests.clear();
        self.size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ironwood::network::{crypto::PublicKey, wire::WirePacketType};
    use ed25519_dalek::SigningKey;

    fn key(b: u8) -> PublicKey {
        SigningKey::from_bytes(&[b; 32]).verifying_key()
    }

    #[derive(Debug)]
    struct Pkt {
        src: PublicKey,
        dst: PublicKey,
        payload: Vec<u8>,
        t: WirePacketType,
    }

    impl Pkt {
        fn new(src: u8, dst: u8, payload: &[u8]) -> Box<dyn PqPacket> {
            Box::new(Self {
                src: key(src),
                dst: key(dst),
                payload: payload.to_vec(),
                t: WirePacketType::Dummy,
            })
        }
    }

    impl WireEncodable for Pkt {
        fn size(&self) -> usize {
            self.payload.len()
        }
        fn encode(&self, out: &mut Vec<u8>) -> Result<(), crate::ironwood::errors::Error> {
            out.extend_from_slice(&self.payload);
            Ok(())
        }
    }

    impl PqPacket for Pkt {
        fn wire_type(&self) -> WirePacketType {
            self.t
        }
        fn source_key(&self) -> PublicKey {
            self.src
        }
        fn dest_key(&self) -> PublicKey {
            self.dst
        }
    }

    fn payload(p: &dyn PqPacket) -> Vec<u8> {
        let mut out = Vec::new();
        p.encode(&mut out).expect("encode");
        out
    }

    #[test]
    fn empty_queue() {
        let mut q = PacketQueue::new();
        assert_eq!(q.size(), 0);
        assert!(q.pop().is_none());
        assert!(q.peek().is_none());
        assert!(!q.drop_oldest());
    }

    #[test]
    fn fifo_within_stream_and_size_accounting() {
        let mut q = PacketQueue::new();
        q.push(Pkt::new(1, 2, b"a"));
        q.push(Pkt::new(1, 2, b"bb"));
        assert_eq!(q.size(), 3);
        assert_eq!(q.peek().expect("peek").1, 1);
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"a");
        assert_eq!(q.size(), 2);
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"bb");
        assert_eq!(q.size(), 0);
        assert!(q.dests.is_empty());
    }

    #[test]
    fn pop_is_globally_oldest_packet() {
        let mut q = PacketQueue::new();
        // A создан первым, но после опустошения его голова новее B.
        q.push(Pkt::new(1, 1, b"a1")); // dest A, t0
        q.push(Pkt::new(1, 2, b"b1")); // dest B, t1
        std::thread::sleep(std::time::Duration::from_millis(2));
        q.push(Pkt::new(1, 1, b"a2")); // dest A, t2 (голова A теперь a2)

        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"a1");
        // Должен уйти b1 (t1), а не a2 (t2), хотя dest A стоит раньше.
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"b1");
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"a2");
    }

    #[test]
    fn drop_oldest_from_largest_pair() {
        let mut q = PacketQueue::new();
        // dest1: source1 (2+2), source2 (1); dest2: source1 (5)
        q.push(Pkt::new(1, 1, b"xx"));
        q.push(Pkt::new(2, 1, b"y"));
        q.push(Pkt::new(1, 1, b"zz"));
        q.push(Pkt::new(3, 2, b"12345"));
        assert_eq!(q.size(), 10);

        // Самая большая пара dest1 -> source1 (4): выкидываем её голову xx.
        assert!(q.drop_oldest());
        assert_eq!(q.size(), 8);

        // Старейший из оставшихся — y (t1), не zz (t2).
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"y");
        assert_eq!(q.size(), 7);

        // Теперь самый большой dest — dest2 (5), из него уходит 12345.
        assert!(q.drop_oldest());
        assert_eq!(q.size(), 2);
        assert_eq!(payload(q.pop().expect("pop").as_ref()), b"zz");
        assert_eq!(q.size(), 0);
        assert!(!q.drop_oldest());
    }
}
