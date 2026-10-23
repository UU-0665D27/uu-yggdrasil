//! IPv6-адреса yggdrasil: побайтовый порт `yggdrasil-go/src/address`.
//!
//! Адрес — 16 байт: префикс `0x02`, число ведущих единиц в инвертированном
//! ключе, затем усечённые биты ключа. `GetKey` восстанавливает частичный
//! ключ (хвост заполнен единицами) — его достаточно для path-lookup.

/// `GetPrefix()`.
pub const PREFIX: u8 = 0x02;

/// `type Address [16]byte`.
pub type Address = [u8; 16];
/// `type Subnet [8]byte`.
pub type Subnet = [u8; 8];

/// `AddrForKey(publicKey)`.
#[must_use]
pub fn addr_for_key(key: &[u8; 32]) -> Address {
    let mut inverted = [0u8; 32];
    for (dst, src) in inverted.iter_mut().zip(key.iter()) {
        *dst = !*src;
    }

    let mut temp = Vec::with_capacity(32);
    let mut done = false;
    let mut ones = 0u8;
    let mut bits = 0u8;
    let mut n_bits = 0u8;

    for idx in 0..256usize {
        let bit = (inverted[idx / 8] >> (7 - (idx % 8))) & 1;
        if !done && bit != 0 {
            ones = ones.wrapping_add(1);
            continue;
        }
        if !done && bit == 0 {
            done = true;
            continue;
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            n_bits = 0;
            temp.push(bits);
        }
    }

    let mut addr = [0u8; 16];
    addr[0] = PREFIX;
    addr[1] = ones;
    let n = temp.len().min(14);
    addr[2..2 + n].copy_from_slice(&temp[..n]);
    addr
}

/// `SubnetForKey(publicKey)` — тот же адрес, но с битом subnet в префиксе.
#[must_use]
pub fn subnet_for_key(key: &[u8; 32]) -> Subnet {
    let addr = addr_for_key(key);
    let mut snet = [0u8; 8];
    snet.copy_from_slice(&addr[..8]);
    snet[0] |= 0x01;
    snet
}

/// `Address.GetKey()` — частичный ed25519-ключ, восстановленный из адреса.
#[must_use]
pub fn addr_get_key(addr: &Address) -> [u8; 32] {
    let mut key = [0u8; 32];
    let ones = usize::from(addr[1]);
    for idx in 0..ones {
        key[idx / 8] |= 0x80 >> (idx % 8);
    }

    let key_offset = ones + 1;
    let addr_offset = 8 + 8; // 8*len(prefix) + 8
    for idx in addr_offset..128usize {
        let mut bits = addr[idx / 8] & (0x80 >> (idx % 8));
        bits <<= idx % 8;
        let key_idx = key_offset + (idx - addr_offset);
        bits >>= key_idx % 8;
        let byte_idx = key_idx / 8;
        if byte_idx >= key.len() {
            break;
        }
        key[byte_idx] |= bits;
    }
    for b in &mut key {
        *b = !*b;
    }
    key
}

/// `Subnet.GetKey()`.
#[must_use]
pub fn subnet_get_key(subnet: &Subnet) -> [u8; 32] {
    let mut addr = [0u8; 16];
    addr[..8].copy_from_slice(subnet);
    addr_get_key(&addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn pubkey(seed: u8) -> [u8; 32] {
        *SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes()
    }

    // Golden из yggdrasil-go/src/address (seed → pub/addr/partial key/subnet).
    const CASES: &[(u8, &str, &str, &str, &str, &str)] = &[
        (
            0x00,
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "020224aec2198a4ade94eae2b97eac87",
            "3b6a27bcceb6a42d62a3a8d02a6f1fffffffffffffffffffffffffffffffffff",
            "030224aec2198a4a",
            "3b6a27bcceb6bfffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            0x01,
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "0200eaee384517ec1cd4055a49a5868b",
            "8a88e3dd7409f195fd52db2d3cba7fffffffffffffffffffffffffffffffffff",
            "0300eaee384517ec",
            "8a88e3dd7409ffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            0x07,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "02002b6b27383ac75bea82155f09d9a2",
            "ea4a6c63e29c520abef5507b132effffffffffffffffffffffffffffffffffff",
            "03002b6b27383ac7",
            "ea4a6c63e29c7fffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            0x42,
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
            "0202f5683973243716ddd66de8f5068a",
            "2152f8d19b791d24453242e15f2ebfffffffffffffffffffffffffffffffffff",
            "0302f56839732437",
            "2152f8d19b791fffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            0xff,
            "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
            "0201257a9b7eed646c2bbb6690d63167",
            "76a1592044a6e4f511265bca73a63fffffffffffffffffffffffffffffffffff",
            "0301257a9b7eed64",
            "76a1592044a6ffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    #[test]
    fn address_derivation_matches_go() {
        for &(seed, pub_hex, addr_hex, key_hex, subnet_hex, subkey_hex) in CASES {
            let pubkey = pubkey(seed);
            assert_eq!(pubkey, unhex::<32>(pub_hex), "seed {seed}");
            let addr = addr_for_key(&pubkey);
            assert_eq!(addr, unhex::<16>(addr_hex), "seed {seed}");
            assert_eq!(addr_get_key(&addr), unhex::<32>(key_hex), "seed {seed}");
            assert_eq!(subnet_for_key(&pubkey), unhex::<8>(subnet_hex));
            assert_eq!(
                subnet_get_key(&subnet_for_key(&pubkey)),
                unhex::<32>(subkey_hex),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn address_is_in_yggdrasil_prefix() {
        for seed in 0u8..=255 {
            let addr = addr_for_key(&pubkey(seed));
            assert_eq!(addr[0], PREFIX);
        }
    }
}
