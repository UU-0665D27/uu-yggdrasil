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
impl From<WirePacketType> for u8 {
    fn from(v: WirePacketType) -> Self {
        v as Self
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(u: u64) -> Vec<u8> {
        let mut v = Vec::new();
        wire_append_uint(&mut v, u);
        v
    }

    #[test]
    fn uvarint_golden() {
        assert_eq!(enc(0), [0]);
        assert_eq!(enc(1), [1]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(300), [0xac, 0x02]);
        assert_eq!(
            enc(u64::MAX),
            [0xff; 9].iter().copied().chain([0x01]).collect::<Vec<_>>()
        );
        assert_eq!(wire_size_uint(u64::MAX), 10);
    }

    #[test]
    fn uvarint_roundtrip() {
        for u in [
            0,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            1 << 32,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let v = enc(u);
            assert_eq!(v.len(), wire_size_uint(u));
            let mut s = v.as_slice();
            assert_eq!(wire_chop_uint(&mut s), Some(u));
            assert!(s.is_empty());
        }
    }

    #[test]
    fn uvarint_rejects_truncated_and_overflow() {
        let mut s: &[u8] = &[0x80];
        assert_eq!(wire_chop_uint(&mut s), None);
        let mut s: &[u8] = &[0xff; 10];
        assert_eq!(wire_chop_uint(&mut s), None);
        let mut s: &[u8] = &[0xff; 9].iter().copied().chain([0x02]).collect::<Vec<_>>();
        assert_eq!(wire_chop_uint(&mut s), None);
    }

    #[test]
    fn path_roundtrip() {
        for path in [vec![], vec![1], vec![1, 300, u64::MAX]] {
            let mut out = Vec::new();
            wire_append_path(&mut out, &path);
            assert_eq!(out.len(), wire_size_path(&path));
            assert_eq!(wire_decode_path(&out), Some((path.clone(), out.len())));

            let mut rest = out.as_slice();
            let mut got = Vec::new();
            assert!(wire_chop_path(&mut got, &mut rest));
            assert_eq!(got, path);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn path_stops_at_first_zero() {
        // 1, 0, 2: путь = [1], после терминатора остаётся 0x02.
        let data = [1u8, 0, 2];
        assert_eq!(wire_decode_path(&data), Some((vec![1], 2)));
        // Нет терминатора.
        assert_eq!(wire_decode_path(&[1, 2]), None);
    }

    #[test]
    fn packet_type_byte() {
        for b in 0u8..=9 {
            let t = WirePacketType::try_from_byte(b).expect("valid");
            assert_eq!(u8::from(t), b);
        }
        assert!(WirePacketType::try_from_byte(10).is_err());
        assert!(WirePacketType::try_from_byte(255).is_err());
    }
}
