//! Крипто-примитивы `encrypted`-слоя.
//!
//! - `edPub`/`edPriv`/`edSig` — Ed25519 (`VerifyingKey`/`SigningKey`/`Signature`).
//! - `boxPub`/`boxPriv`/`boxShared`/`boxNonce` — X25519 + `NaCl` box.
//! - `e2c` — конверсия Ed25519 → X25519.
//! - `groupAuth` — preimage для подписи handshake'а.

use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey, aead::Aead};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

/// `edPubSize`.
pub const ED_PUB_SIZE: usize = 32;
/// `edPrivSize`.
pub const ED_PRIV_SIZE: usize = 64;
/// `edSigSize`.
pub const ED_SIG_SIZE: usize = 64;

/// `boxPubSize`.
pub const BOX_PUB_SIZE: usize = 32;
/// `boxPrivSize`.
pub const BOX_PRIV_SIZE: usize = 32;
/// `boxSharedSize`.
pub const BOX_SHARED_SIZE: usize = 32;
/// `boxNonceSize`.
pub const BOX_NONCE_SIZE: usize = 24;
/// `box.Overhead` — Poly1305-тег.
pub const BOX_OVERHEAD: usize = 16;

/// `edPub` — `VerifyingKey` (`as_bytes()` = edPub).
pub type EdPub = VerifyingKey;
/// `edPriv` — `SigningKey` (`to_bytes()` = 32-байтовый seed).
pub type EdPriv = SigningKey;
/// `edSig` — `ed25519_dalek::Signature`.
pub type EdSig = Signature;

/// `boxPub`.
pub type BoxPub = [u8; BOX_PUB_SIZE];
/// `boxPriv`.
pub type BoxPriv = [u8; BOX_PRIV_SIZE];
/// `boxNonce`.
pub type BoxNonce = [u8; BOX_NONCE_SIZE];

// ────────────── ed25519 ──────────────

/// `func edSign(msg, priv, preimage)`.
#[must_use]
pub fn ed_sign(msg: &[u8], priv_key: &EdPriv, preimage: Option<&[u8]>) -> EdSig {
    match preimage {
        Some(pre) if !pre.is_empty() => {
            let mut buf = Vec::with_capacity(pre.len() + msg.len());
            buf.extend_from_slice(pre);
            buf.extend_from_slice(msg);
            priv_key.sign(&buf)
        }
        _ => priv_key.sign(msg),
    }
}

/// `func edCheck(msg, sig, pub, preimage)`.
#[must_use]
pub fn ed_check(msg: &[u8], sig: &EdSig, pub_key: &EdPub, preimage: Option<&[u8]>) -> bool {
    let res = match preimage {
        Some(pre) if !pre.is_empty() => {
            let mut buf = Vec::with_capacity(pre.len() + msg.len());
            buf.extend_from_slice(pre);
            buf.extend_from_slice(msg);
            pub_key.verify(&buf, sig)
        }
        _ => pub_key.verify(msg, sig),
    };
    res.is_ok()
}

// ────────────── e2c (Ed25519 → X25519) ──────────────

/// `func Ed25519PublicKeyToCurve25519(pk)` — y-координата → u-координата.
/// Аналог `golang.org/x/crypto/curve25519` через `EdwardsPoint::to_montgomery`.
///
/// # Panics
/// Не паникует при валидном `VerifyingKey` — `dalek` гарантирует, что это
/// точка на кривой; `decompress()` всегда `Some`.
#[must_use]
pub fn ed25519_pub_to_curve25519(pub_key: &EdPub) -> BoxPub {
    let compressed = CompressedEdwardsY(*pub_key.as_bytes());
    let ed_point = compressed
        .decompress()
        .expect("VerifyingKey is always a valid Edwards point");
    *ed_point.to_montgomery().as_bytes()
}

/// `func Ed25519PrivateKeyToCurve25519(pk)` — `sha512(seed)[..32]` с
/// клэмпингом (RFC 7748).
#[must_use]
pub fn ed25519_priv_to_curve25519(priv_key: &EdPriv) -> BoxPriv {
    let seed = priv_key.to_bytes();
    let hash = Sha512::digest(seed);
    let mut out = [0u8; BOX_PRIV_SIZE];
    out.copy_from_slice(&hash[..BOX_PRIV_SIZE]);

    // clamp (RFC 7748)
    out[0] &= 0b1111_1000;
    out[31] &= 0b0111_1111;
    out[31] |= 0b0100_0000;
    out
}

// ────────────── box ──────────────

/// `newBoxKeys` — случайная X25519-пара.
///
/// # Panics
/// Паникует, если OS RNG недоступен (`getrandom` вернул ошибку) — как
/// `panic("failed to generate keys")` в Go-версии.
#[must_use]
pub fn new_box_keys() -> (BoxPub, BoxPriv) {
    let mut secret_bytes = [0u8; BOX_PRIV_SIZE];
    // Не паникуем при сбое OS RNG — Go в этом случае тоже паникует
    // (`panic("failed to generate keys")`). Оставляем как есть.
    getrandom::fill(&mut secret_bytes).expect("OS RNG");
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    (*public.as_bytes(), *secret.as_bytes())
}

/// `getShared(out, pub, priv)` — precompute DH shared secret.
/// В Rust возвращаем `SalsaBox`, который инкапсулирует precompute.
#[must_use]
pub fn get_shared(their_pub: &BoxPub, our_secret: &BoxPriv) -> SalsaBox {
    let pk = PublicKey::from(*their_pub);
    let sk = SecretKey::from(*our_secret);
    SalsaBox::new(&pk, &sk)
}

/// `nonceForUint64(u64)` — 24 байта, последние 8 — big-endian.
#[must_use]
pub fn nonce_for_uint64(u64_val: u64) -> BoxNonce {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    nonce[BOX_NONCE_SIZE - 8..].copy_from_slice(&u64_val.to_be_bytes());
    nonce
}

/// `boxSeal(out, msg, nonce, shared)` — `XSalsa20Poly1305` seal.
///
/// # Panics
/// Не паникует: `SalsaBox::encrypt` ошибается только на превышении лимита
/// длины, что на практике недостижимо (лимит — 2^64 байт).
#[must_use]
pub fn box_seal(shared: &SalsaBox, msg: &[u8], nonce: u64) -> Vec<u8> {
    let n = nonce_for_uint64(nonce);
    let nonce_arr = Nonce::from(n);
    shared
        .encrypt(&nonce_arr, msg)
        .expect("SalsaBox::encrypt: message too long")
}

/// `boxOpen(out, boxed, nonce, shared)` — вернуть plaintext или `None`.
#[must_use]
pub fn box_open(shared: &SalsaBox, boxed: &[u8], nonce: u64) -> Option<Vec<u8>> {
    let n = nonce_for_uint64(nonce);
    let nonce_arr = Nonce::from(n);
    shared.decrypt(&nonce_arr, boxed).ok()
}

// ────────────── group auth ──────────────

/// `type groupAuth struct { enabled, secret }`.
#[derive(Debug, Clone)]
pub struct GroupAuth {
    enabled: bool,
    secret: [u8; 32],
}

impl GroupAuth {
    /// `newGroupAuth(password)`. Пустая строка — отключено.
    #[must_use]
    pub fn new(password: &str) -> Self {
        if password.is_empty() {
            return Self {
                enabled: false,
                secret: [0u8; 32],
            };
        }
        let mut hasher = Sha256::new();
        hasher.update(b"ironwood/encrypted\0");
        hasher.update(password.as_bytes());
        Self {
            enabled: true,
            secret: hasher.finalize().into(),
        }
    }

    /// `func (auth groupAuth) preimage() []byte`.
    #[must_use]
    pub const fn preimage(&self) -> Option<&[u8; 32]> {
        if self.enabled {
            Some(&self.secret)
        } else {
            None
        }
    }
}

impl Default for GroupAuth {
    fn default() -> Self {
        Self::new("")
    }
}

// ────────────── sanity ──────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2c_roundtrip() {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(b"testseed");
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();

        let pk_mont = ed25519_pub_to_curve25519(&pk);
        let sk_mont = ed25519_priv_to_curve25519(&sk);

        // ECDH должен совпадать в обе стороны.
        let (b_pub, b_priv) = new_box_keys();
        let s_a = get_shared(&b_pub, &sk_mont);
        let s_b = get_shared(&pk_mont, &b_priv);

        let msg = b"hello";
        let sealed = box_seal(&s_a, msg, 42);
        let opened = box_open(&s_b, &sealed, 42).expect("open");
        assert_eq!(opened, msg);
    }

    #[test]
    fn ed_sign_with_preimage() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let pk = sk.verifying_key();
        let pre = b"preimage";
        let msg = b"message";
        let sig = ed_sign(msg, &sk, Some(pre));
        assert!(ed_check(msg, &sig, &pk, Some(pre)));
        assert!(!ed_check(msg, &sig, &pk, None));
    }
}
