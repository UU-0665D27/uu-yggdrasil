//! Bloom-фильтр ironwood: 8192 бита, 8 хешей, wire-формат Go-совместим
//! (плотная упаковка с флагами нулевых/единичных чанков).
//!
//! Хеш — FNV-1 (Go `fnv.New64()`), страйд-техника Кирша–Мицценмахера
//! `h_i = h1 + i*h2` — как в `bits-and-blooms/bloom` v3.

use crate::ironwood::{
    errors::Error,
    network::{
        crypto::PublicKey,
        wire::{WireEncodable, wire_chop_slice},
    },
};

/// Байт флагов «нулевой»/«все единицы» для чанков.
pub const BLOOM_FILTER_F: usize = 16;
/// Кол-во u64-чанков.
pub const BLOOM_FILTER_U: usize = 128;
/// Бит в фильтре.
pub const BLOOM_FILTER_M: usize = BLOOM_FILTER_U * 64;
/// Кол-во хешей.
pub const BLOOM_FILTER_K: u64 = 8;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1 64-bit (Go `fnv.New64()`, не `New64a`).
fn fnv1_64(data: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in data {
        h = h.wrapping_mul(FNV_PRIME);
        h ^= u64::from(b);
    }
    h
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
        let h = fnv1_64(data);
        let b = h.to_le_bytes();
        let h1 = u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let h2 = u64::from(u32::from_le_bytes([b[4], b[5], b[6], b[7]]));
        for i in 0..BLOOM_FILTER_K {
            let combined = h1.wrapping_add(i.wrapping_mul(h2));
            let bit = usize::try_from(combined % BLOOM_FILTER_M as u64).unwrap_or(0);
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
        let h = fnv1_64(data);
        let b = h.to_le_bytes();
        let h1 = u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        let h2 = u64::from(u32::from_le_bytes([b[4], b[5], b[6], b[7]]));
        for i in 0..BLOOM_FILTER_K {
            let combined = h1.wrapping_add(i.wrapping_mul(h2));
            let bit = usize::try_from(combined % BLOOM_FILTER_M as u64).unwrap_or(0);
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
