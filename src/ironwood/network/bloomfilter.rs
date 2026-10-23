//! Bloom-фильтр ironwood: 8192 бита, 8 хешей, wire-формат Go-совместим
//! (плотная упаковка с флагами нулевых/единичных чанков).
//!
//! Хеширование побайтово совместимо с `bits-and-blooms/bloom` v3:
//! murmur3 x64_128 (`sum256` → 4 u64) и функция `location` из библиотеки.

use crate::ironwood::{
    errors::Error,
    network::{
        crypto::PublicKey,
        wire::{WireEncodable, wire_chop_slice},
    },
};
use std::collections::HashMap;

/// Байт флагов «нулевой»/«все единицы» для чанков.
pub const BLOOM_FILTER_F: usize = 16;
/// Кол-во u64-чанков.
pub const BLOOM_FILTER_U: usize = 128;
/// Бит в фильтре.
pub const BLOOM_FILTER_M: usize = BLOOM_FILTER_U * 64;
/// Кол-во хешей.
pub const BLOOM_FILTER_K: u64 = 8;

const C1_128: u64 = 0x87c3_7b91_1142_53d5;
const C2_128: u64 = 0x4cf5_ad43_2745_937f;

/// murmur3 x64_128, `digest128` из `bits-and-blooms/bloom` v3.
struct Digest128 {
    h1: u64,
    h2: u64,
}

impl Digest128 {
    fn new() -> Self {
        Self { h1: 0, h2: 0 }
    }

    fn bmix_words(&mut self, k1: u64, k2: u64) {
        let mut k1 = k1.wrapping_mul(C1_128);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2_128);
        self.h1 ^= k1;

        self.h1 = self.h1.rotate_left(27);
        self.h1 = self.h1.wrapping_add(self.h2);
        self.h1 = self.h1.wrapping_mul(5).wrapping_add(0x52dc_e729);

        let mut k2 = k2.wrapping_mul(C2_128);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1_128);
        self.h2 ^= k2;

        self.h2 = self.h2.rotate_left(31);
        self.h2 = self.h2.wrapping_add(self.h1);
        self.h2 = self.h2.wrapping_mul(5).wrapping_add(0x3849_5ab5);
    }

    fn bmix(&mut self, data: &[u8]) {
        for block in data.chunks_exact(16) {
            let k1 = u64::from_le_bytes(block[..8].try_into().unwrap_or([0; 8]));
            let k2 = u64::from_le_bytes(block[8..].try_into().unwrap_or([0; 8]));
            self.bmix_words(k1, k2);
        }
    }

    /// `sum128` для хвоста длиной `< 16` (без «виртуального» байта).
    fn sum128(&self, length: u64, tail: &[u8]) -> (u64, u64) {
        let mut k1 = 0u64;
        let mut k2 = 0u64;
        for (i, &b) in tail.iter().enumerate().take(8) {
            k1 |= u64::from(b) << (8 * i);
        }
        for (i, &b) in tail.iter().enumerate().skip(8) {
            k2 |= u64::from(b) << (8 * (i - 8));
        }

        let mut h1 = self.h1;
        let mut h2 = self.h2;
        if tail.len() >= 9 {
            let mut k2 = k2.wrapping_mul(C2_128);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1_128);
            h2 ^= k2;
        }
        if !tail.is_empty() {
            let mut k1 = k1.wrapping_mul(C1_128);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2_128);
            h1 ^= k1;
        }

        h1 ^= length;
        h2 ^= length;
        h1 = h1.wrapping_add(h2);
        h2 = h2.wrapping_add(h1);
        h1 = fmix64(h1);
        h2 = fmix64(h2);
        h1 = h1.wrapping_add(h2);
        h2 = h2.wrapping_add(h1);
        (h1, h2)
    }

    /// `sum256`: четыре 64-битных хеша.
    fn sum256(&mut self, data: &[u8]) -> [u64; 4] {
        self.h1 = 0;
        self.h2 = 0;
        self.bmix(data);

        let length = data.len() as u64;
        let tail_len = data.len() % 16;
        let tail = &data[data.len() - tail_len..];
        let (hash1, hash2) = self.sum128(length, tail);

        let (hash3, hash4) = if tail_len + 1 == 16 {
            let word1 = u64::from_le_bytes(tail[..8].try_into().unwrap_or([0; 8]));
            let mut word2 = u64::from_le_bytes([
                tail[8], tail[9], tail[10], tail[11], tail[12], tail[13], tail[14], 0,
            ]);
            word2 |= 1u64 << 56;
            self.bmix_words(word1, word2);
            self.sum128(length + 1, &[])
        } else {
            let mut padded = [0u8; 16];
            padded[..tail_len].copy_from_slice(tail);
            padded[tail_len] = 1;
            self.sum128(length + 1, &padded[..=tail_len])
        };
        [hash1, hash2, hash3, hash4]
    }
}

fn fmix64(k: u64) -> u64 {
    let mut k = k;
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

/// `location(h, i)` из `bits-and-blooms/bloom`.
fn location(h: [u64; 4], i: u64) -> u64 {
    let idx = (i + (i % 2)) % 4;
    h[usize::try_from(i % 2).unwrap_or(0)]
        .wrapping_add(i.wrapping_mul(h[usize::try_from(2 + idx / 2).unwrap_or(0)]))
}

fn hash_locations(data: &[u8]) -> impl Iterator<Item = usize> {
    let h = Digest128::new().sum256(data);
    (0..BLOOM_FILTER_K)
        .map(move |i| usize::try_from(location(h, i) % BLOOM_FILTER_M as u64).unwrap_or(0))
}

/// `bloom` — 8192-битный фильтр.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bloom {
    bits: [u64; BLOOM_FILTER_U],
}

impl Bloom {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bits: [0u64; BLOOM_FILTER_U],
        }
    }

    /// `func (b *bloom) addKey(key)`.
    pub fn add_key(&mut self, key: &PublicKey) {
        self.add_bytes(key.as_bytes());
    }

    /// Добавить произвольные байты — используется и для `xKey` трансформаций.
    pub fn add_bytes(&mut self, data: &[u8]) {
        for bit in hash_locations(data) {
            self.bits[bit / 64] |= 1u64 << (bit % 64);
        }
    }

    /// `func (b *bloom) addFilter(f)` — OR с другим битсетом.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    /// Возможно, `data` в фильтре (`true` = возможно, `false` = точно нет).
    #[must_use]
    pub fn test(&self, data: &[u8]) -> bool {
        for bit in hash_locations(data) {
            if self.bits[bit / 64] & (1u64 << (bit % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт, либо при
    /// одновременных флагах «0» и «все единицы» для одного чанка.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;

        let mut flags0 = [0u8; BLOOM_FILTER_F];
        if !wire_chop_slice(&mut flags0, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut flags1 = [0u8; BLOOM_FILTER_F];
        if !wire_chop_slice(&mut flags1, &mut rest) {
            return Err(Error::DECODE);
        }

        let mut bits = [0u64; BLOOM_FILTER_U];
        for (idx, chunk) in bits.iter_mut().enumerate() {
            let byte = idx / 8;
            let mask = 0x80u8 >> (idx % 8);
            let is_zero = flags0[byte] & mask != 0;
            let is_ones = flags1[byte] & mask != 0;
            if is_zero && is_ones {
                return Err(Error::DECODE);
            } else if is_zero {
                // остаётся 0
            } else if is_ones {
                *chunk = u64::MAX;
            } else {
                if rest.len() < 8 {
                    return Err(Error::DECODE);
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&rest[..8]);
                *chunk = u64::from_be_bytes(buf);
                rest = &rest[8..];
            }
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(Self { bits })
    }
}

impl Default for Bloom {
    fn default() -> Self {
        Self::new()
    }
}

impl WireEncodable for Bloom {
    fn size(&self) -> usize {
        let mut size = BLOOM_FILTER_F * 2;
        for &chunk in &self.bits {
            if chunk != 0 && chunk != u64::MAX {
                size += 8;
            }
        }
        size
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut flags0 = [0u8; BLOOM_FILTER_F];
        let mut flags1 = [0u8; BLOOM_FILTER_F];
        let mut packed: Vec<u64> = Vec::new();
        for (idx, &chunk) in self.bits.iter().enumerate() {
            if chunk == 0 {
                flags0[idx / 8] |= 0x80u8 >> (idx % 8);
            } else if chunk == u64::MAX {
                flags1[idx / 8] |= 0x80u8 >> (idx % 8);
            } else {
                packed.push(chunk);
            }
        }
        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);
        for chunk in packed {
            out.extend_from_slice(&chunk.to_be_bytes());
        }
        Ok(())
    }
}

/// Состояние одного пира в `Blooms`.
#[derive(Debug, Clone, Default)]
pub struct BloomInfo {
    /// Что мы последний раз отправили этому пиру.
    pub send: Bloom,
    /// Что мы получили от пира.
    pub recv: Bloom,
    /// Счётчик «давно не отправляли» (форс-ре-отправка раз в 3600 циклов).
    pub seq: u16,
    /// Пир на дереве (нам разрешено слать ему multicat'ы).
    pub on_tree: bool,
    /// Флаг «оставляем 1-биты» — защита от flapping'а.
    pub z_dirty: bool,
}

/// `blooms` из `bloomfilter.go` — состояния всех пиров.
#[derive(Debug, Default)]
pub struct Blooms {
    inner: HashMap<PublicKey, BloomInfo>,
}

impl Blooms {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_info(&mut self, key: PublicKey) {
        self.inner.entry(key).or_default();
    }

    pub fn remove_info(&mut self, key: &PublicKey) {
        self.inner.remove(key);
    }

    #[must_use]
    pub fn on_tree(&self, key: &PublicKey) -> bool {
        self.inner.get(key).is_some_and(|i| i.on_tree)
    }

    pub fn handle_bloom(&mut self, from: &PublicKey, b: Bloom) {
        if let Some(info) = self.inner.get_mut(from) {
            info.recv = b;
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &BloomInfo)> {
        self.inner.iter()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub(crate) fn get_mut(&mut self, key: &PublicKey) -> Option<&mut BloomInfo> {
        self.inner.get_mut(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let b = s.as_bytes();
        for pair in b.chunks_exact(2) {
            let hi = (pair[0] as char).to_digit(16).expect("hex");
            let lo = (pair[1] as char).to_digit(16).expect("hex");
            out.push(u8::try_from(hi * 16 + lo).expect("byte"));
        }
        out
    }

    fn hex(v: &[u8]) -> String {
        use std::fmt::Write as _;
        v.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    // Golden values получены из Go: bits-and-blooms/bloom v3.7.1.
    const EMPTY: &str = "ffffffffffffffffffffffffffffffff00000000000000000000000000000000";
    const ADD_01: &str = "ffffffffffffeffeffffffebfffffa3f0000000000000000000000000000000000000000000000400000000000000004000004000000000000000040000000000000000010000000000000000100000000000000004000000004000000000000";

    #[test]
    fn empty_encode_matches_go() {
        let mut out = Vec::new();
        Bloom::new().encode(&mut out).expect("encode");
        assert_eq!(hex(&out), EMPTY);
        assert_eq!(out.len(), Bloom::new().size());
    }

    #[test]
    fn add_encode_matches_go() {
        let mut b = Bloom::new();
        b.add_bytes(&[1]);
        let mut out = Vec::new();
        b.encode(&mut out).expect("encode");
        assert_eq!(hex(&out), ADD_01);
        assert_eq!(out.len(), b.size());
        assert!(b.test(&[1]));
        assert!(!b.test(&[2]));
        assert!(!b.test(b"hello"));
    }

    #[test]
    fn decode_roundtrip() {
        let mut b = Bloom::new();
        b.add_bytes(&[1]);
        b.add_bytes(&[0, 0, 0, 0]);
        b.add_bytes(b"hello");
        let mut out = Vec::new();
        b.encode(&mut out).expect("encode");
        let d = Bloom::decode(&out).expect("decode");
        assert_eq!(b, d);
        assert_eq!(d.size(), b.size());
    }

    #[test]
    fn merge_ors_bits() {
        let mut a = Bloom::new();
        a.add_bytes(&[1]);
        let mut b = Bloom::new();
        b.add_bytes(&[2]);
        let mut both = a.clone();
        both.merge(&b);
        assert!(both.test(&[1]));
        assert!(both.test(&[2]));
        assert!(!a.test(&[2]));
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(Bloom::decode(&[]).is_err());
        assert!(Bloom::decode(&[0u8; 31]).is_err());
        assert!(Bloom::decode(&[0u8; 33]).is_err());

        // Один и тот же чанк помечен и как нулевой, и как all-ones.
        let mut bad = unhex(EMPTY);
        bad[0] = 0x80;
        bad[16] = 0x80;
        assert_eq!(bad[0] & bad[16], 0x80);
        assert!(Bloom::decode(&bad).is_err());

        // Не хватает упакованного чанка.
        let short = &unhex(ADD_01)[..39];
        assert!(Bloom::decode(short).is_err());

        // Лишние байты в конце.
        let mut long = unhex(EMPTY);
        long.push(0);
        assert!(Bloom::decode(&long).is_err());
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    fn words(b: &Bloom) -> Vec<(usize, u64)> {
        b.bits
            .iter()
            .enumerate()
            .filter(|&(_, &w)| w != 0)
            .map(|(i, &w)| (i, w))
            .collect()
    }

    // Golden из Go bits-and-blooms v3.7.1 (проверяет murmur-tail и bmix).
    #[test]
    fn murmur_locations_match_go() {
        let pattern: Vec<u8> = (0..100u8).collect();
        let cases: [(&[u8], &[(usize, u64)]); 5] = [
            (
                &[0x11; 15],
                &[
                    (49, 2097152),
                    (64, 8388608),
                    (73, 67108864),
                    (82, 16384),
                    (99, 524288),
                    (107, 536870912),
                    (108, 128),
                    (122, 2147483648),
                ],
            ),
            (
                &[0x22; 16],
                &[
                    (1, 4398046511104),
                    (19, 1073741824),
                    (25, 576460752303423488),
                    (28, 16384),
                    (43, 140737488355328),
                    (57, 18014398509481984),
                    (81, 4194304),
                    (110, 4611686018427387904),
                ],
            ),
            (
                &[0x33; 17],
                &[
                    (9, 281474976710656),
                    (25, 281474976710656),
                    (30, 1125899906842624),
                    (42, 17592186044416),
                    (58, 17592186044416),
                    (72, 18014398509481984),
                    (73, 8192),
                    (115, 131072),
                ],
            ),
            (
                &[0x42; 32],
                &[
                    (6, 140737488355328),
                    (8, 72057594037927936),
                    (47, 2),
                    (58, 4503599627370496),
                    (67, 1152921504606846976),
                    (72, 8192),
                    (84, 2251799813685248),
                    (93, 256),
                ],
            ),
            (
                &pattern,
                &[
                    (12, 4),
                    (16, 288230376151711744),
                    (24, 64),
                    (36, 67108864),
                    (59, 64),
                    (67, 131072),
                    (71, 1024),
                    (86, 562949953421312),
                ],
            ),
        ];
        for (data, expected) in cases {
            let mut b = Bloom::new();
            b.add_bytes(data);
            assert_eq!(words(&b), expected, "data len {}", data.len());
        }
    }
}
