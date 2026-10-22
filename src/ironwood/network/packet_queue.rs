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
    #[allow(dead_code)]
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
        let dest = self.dests.first_mut()?;
        let source = dest.sources.first_mut()?;
        let info = source.infos.pop_front()?;

        source.size -= info.size;
        dest.size -= info.size;
        self.size -= info.size;

        if source.infos.is_empty() {
            dest.sources.remove(0);
        }
        if dest.sources.is_empty() {
            self.dests.remove(0);
        }

        Some(info.packet)
    }

    /// `func (q *packetQueue) peek()`.
    #[must_use]
    pub fn peek(&self) -> Option<(&dyn PqPacket, u64)> {
        let dest = self.dests.first()?;
        let source = dest.sources.first()?;
        let info = source.infos.front()?;
        Some((info.packet.as_ref(), info.size))
    }

    /// `func (q *packetQueue) drop()` — выкинуть самый старый пакет из самой
    /// длинной пары (dest → source). Возвращает `false` если очередь пуста.
    pub fn drop_oldest(&mut self) -> bool {
        if self.size == 0 {
            return false;
        }

        let Some(dest_idx) = self
            .dests
            .iter()
            .enumerate()
            .max_by_key(|(_, d)| d.size)
            .map(|(i, _)| i)
        else {
            return false;
        };

        let dest = &mut self.dests[dest_idx];
        let Some(source_idx) = dest
            .sources
            .iter()
            .enumerate()
            .max_by_key(|(_, s)| s.size)
            .map(|(i, _)| i)
        else {
            return false;
        };

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
