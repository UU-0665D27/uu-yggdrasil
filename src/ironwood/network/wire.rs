//! Wire-формат ironwood: varint, path, типы сообщений.
//! Go-совместим побайтово.

use crate::ironwood::errors::Error;

const MAX_VARINT_LEN: usize = 10;

/// `type peerPort uint64` из Go. 0 зарезервирован под terminator пути.
pub type PeerPort = u64;

/// `type wirePacketType byte`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WirePacketType {
    Dummy = 0,
    KeepAlive = 1,
    ProtoSigReq = 2,
    ProtoSigRes = 3,
    ProtoAnnounce = 4,
    ProtoBloomFilter = 5,
    ProtoPathLookup = 6,
    ProtoPathNotify = 7,
    ProtoPathBroken = 8,
    Traffic = 9,
}

impl WirePacketType {
    /// # Errors
    /// [`Error::UNRECOGNIZED_MESSAGE`] если байт вне диапазона.
    pub const fn try_from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0 => Self::Dummy,
            1 => Self::KeepAlive,
            2 => Self::ProtoSigReq,
            3 => Self::ProtoSigRes,
            4 => Self::ProtoAnnounce,
            5 => Self::ProtoBloomFilter,
            6 => Self::ProtoPathLookup,
            7 => Self::ProtoPathNotify,
            8 => Self::ProtoPathBroken,
            9 => Self::Traffic,
            _ => return Err(Error::UNRECOGNIZED_MESSAGE),
        })
    }
}

// ──────────────── varint ────────────────

/// Длина Uvarint без аллокации. Аналог `wireSizeUint`.
#[must_use]
pub const fn wire_size_uint(mut u: u64) -> usize {
    let mut size = 1;
    while u >= 0x80 {
        u >>= 7;
        size += 1;
    }
    size
}

/// Аналог `wireAppendUint` (`binary.AppendUvarint`).
///
/// `u.to_le_bytes()[0]` — младший байт `u`, что и требовалось: Uvarint
/// кодирует младшие 7 бит на байт, старший бит байта — continuation.
pub fn wire_append_uint(out: &mut Vec<u8>, mut u: u64) {
    while u >= 0x80 {
        // low-байт + continuation-флаг; старшие 7 бит уйдут в следующие итерации.
        out.push(u.to_le_bytes()[0] | 0x80);
        u >>= 7;
    }
    // На выходе из цикла u < 0x80, поэтому старший бит low-байта = 0.
    out.push(u.to_le_bytes()[0]);
}
/// Аналог `wireChopUint` (`binary.Uvarint`). Читает и сдвигает `data`.
/// Возвращает `None` на битом или неполном varint.
pub fn wire_chop_uint(data: &mut &[u8]) -> Option<u64> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in data.iter().enumerate() {
        if i == MAX_VARINT_LEN {
            return None;
        }
        if b < 0x80 {
            // Переполнение: 10-й байт не должен быть > 1.
            if i == MAX_VARINT_LEN - 1 && b > 1 {
                return None;
            }
            x |= u64::from(b) << s;
            *data = &data[i + 1..];
            return Some(x);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    None
}

// ──────────────── slice ────────────────

/// Аналог `wireChopSlice`: копирует ровно `out.len()` байт, сдвигает `data`.
pub fn wire_chop_slice(out: &mut [u8], data: &mut &[u8]) -> bool {
    if data.len() < out.len() {
        return false;
    }
    out.copy_from_slice(&data[..out.len()]);
    *data = &data[out.len()..];
    true
}

/// Аналог `wireChopBytes`: читает `size` байт в Vec.
pub fn wire_chop_bytes(out: &mut Vec<u8>, data: &mut &[u8], size: usize) -> bool {
    if data.len() < size {
        return false;
    }
    out.extend_from_slice(&data[..size]);
    *data = &data[size..];
    true
}

// ──────────────── path ────────────────

/// Аналог `wireSizePath`.
#[must_use]
pub fn wire_size_path(path: &[PeerPort]) -> usize {
    path.iter().map(|&p| wire_size_uint(p)).sum::<usize>() + wire_size_uint(0)
}

/// Аналог `wireAppendPath`: порты через Uvarint, затем 0.
pub fn wire_append_path(out: &mut Vec<u8>, path: &[PeerPort]) {
    for &p in path {
        wire_append_uint(out, p);
    }
    wire_append_uint(out, 0);
}

/// Аналог `wireDecodePath`: читает до первого 0.
/// Возвращает `(путь, прочитанные байты)` или `None` при ошибке.
#[must_use]
pub fn wire_decode_path(data: &[u8]) -> Option<(Vec<PeerPort>, usize)> {
    let mut rest = data;
    let mut path = Vec::new();
    loop {
        let u = wire_chop_uint(&mut rest)?;
        if u == 0 {
            break;
        }
        path.push(u);
    }
    Some((path, data.len() - rest.len()))
}

/// Аналог `wireChopPath`.
pub fn wire_chop_path(out: &mut Vec<PeerPort>, data: &mut &[u8]) -> bool {
    match wire_decode_path(data) {
        Some((path, len)) => {
            out.extend_from_slice(&path);
            *data = &data[len..];
            true
        }
        None => false,
    }
}

// ──────────────── общий трейт ────────────────

/// `wireEncodeable`.
pub trait WireEncodable {
    fn size(&self) -> usize;
    /// Записывает тело пакета в `out` (без байта типа).
    ///
    /// # Errors
    /// Ошибка кодирования конкретной реализации — обычно [`Error::ENCODE`].
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error>;
}

/// `wireEncode`: байт типа + тело.
///
/// # Errors
/// Пробрасывает `encode`.
pub fn wire_encode(
    out: &mut Vec<u8>,
    ptype: WirePacketType,
    obj: &dyn WireEncodable,
) -> Result<(), Error> {
    out.push(ptype as u8);
    obj.encode(out)
}
