use crate::ironwood::types::addr::KeyAddr;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// `ed25519.PublicKeySize` — 32.
pub const PUBLIC_KEY_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// `ed25519.PrivateKeySize` — 64 (seed(32) || public(32)).
pub const PRIVATE_KEY_SIZE: usize = 64;
/// `ed25519.SignatureSize` — 64.
pub const SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// `type publicKey [32]byte`.
pub type PublicKey = VerifyingKey;

/// `type privateKey [64]byte`.
pub type PrivateKey = SigningKey;

/// `type signature [64]byte`.
pub type Signature = ed25519_dalek::Signature;

/// Проверка публичного ключа, совместимая с `types.IsPublicKeyValid`
/// из ironwood: ключ должен канонически раскладываться в точку Ed25519 и
/// не быть точкой малого порядка (включая identity).
#[must_use]
pub fn is_public_key_valid(bytes: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    let Some(point) = CompressedEdwardsY(*bytes).decompress() else {
        return false;
    };
    if point.compress().to_bytes() != *bytes {
        return false;
    }
    !point.is_small_order()
}

/// Разобрать публичный ключ с проверкой [`is_public_key_valid`].
#[must_use]
pub fn public_key_from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Option<PublicKey> {
    if !is_public_key_valid(bytes) {
        return None;
    }
    VerifyingKey::from_bytes(bytes).ok()
}

/// `type crypto struct { privateKey; publicKey }`.
pub struct Crypto {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Crypto {
    /// `init` из Go, вызываемый как конструктор: `secret` — 32-байтовый seed
    /// (первые 32 байта от Go-шного `ed25519.PrivateKey`).
    #[must_use]
    pub fn new(seed: &[u8; 32]) -> Self {
        let private_key = SigningKey::from_bytes(seed);
        let public_key = private_key.verifying_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Если у тебя уже есть `SigningKey` (например, из конфига) —
    /// не пересобирай seed обратно.
    #[must_use]
    pub fn from_signing_key(private_key: SigningKey) -> Self {
        let public_key = private_key.verifying_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// `func (c *crypto) init(secret)` — переинициализация на месте.
    pub fn init(&mut self, seed: &[u8; 32]) {
        self.private_key = SigningKey::from_bytes(seed);
        self.public_key = self.private_key.verifying_key();
    }

    #[must_use]
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// `func (key *privateKey) sign(message) signature`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message)
    }

    /// `func (key *publicKey) verify(message, sig) bool`.
    /// Используем `verify_strict` — аналог по строгости `crypto/ed25519.Verify`
    /// в Go (там тоже проверяется каноничность и отсутствие малой подгруппы).
    #[must_use]
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        self.public_key.verify_strict(message, sig).is_ok()
    }
}

// ──────────────── Свободные функции над `PublicKey` ──────────────────
// В Go это методы `publicKey`, но `PublicKey` = чужой тип `VerifyingKey`,
// поэтому методы добавлять нельзя (orphan rule) — делаем free functions.

/// `func (key *publicKey) verify(message, sig) bool`.
#[must_use]
pub fn public_key_verify(key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    key.verify_strict(message, sig).is_ok()
}

/// `func (key publicKey) less(comparedKey) bool` — побайтовое сравнение.
/// `VerifyingKey` уже реализует `Ord` в dalek v2, так что `<` достаточно;
/// оставлено как явная функция для точного соответствия Go-API.
#[must_use]
pub fn public_key_less(a: &PublicKey, b: &PublicKey) -> bool {
    a.as_bytes() < b.as_bytes()
}

/// `func (key publicKey) addr() types.Addr`.
#[must_use]
pub const fn public_key_addr(key: PublicKey) -> KeyAddr {
    KeyAddr(key)
}

// `toEd` в Go — no-op (слайс и так `ed25519.PublicKey`). В Rust `PublicKey`
// и есть `VerifyingKey`, так что метод не нужен — просто передавай по значению.

// `privateKey.equal` в Go — неконстантное сравнение `==` над `[64]byte`.
// В Rust `SigningKey` намеренно не реализует `PartialEq`; если очень нужно,
// сравнивай seed'ы. Для безопасности используй `subtle::ConstantTimeEq`.
#[must_use]
pub fn private_key_equal(a: &PrivateKey, b: &PrivateKey) -> bool {
    a.to_bytes() == b.to_bytes()
}

/// Полный 64-байтовый формат Go: `seed || public`.
/// Пригодится для сериализации в wire-формате, совместимом с Go.
#[must_use]
pub fn private_key_expanded(key: &PrivateKey) -> [u8; PRIVATE_KEY_SIZE] {
    let mut out = [0u8; PRIVATE_KEY_SIZE];
    out[..32].copy_from_slice(&key.to_bytes());
    out[32..].copy_from_slice(key.verifying_key().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let c = Crypto::new(&[7u8; 32]);
        let sig = c.sign(b"this is a test");
        assert!(c.verify(b"this is a test", &sig));
        assert!(!c.verify(b"this is a tesT", &sig));
    }

    #[test]
    fn public_key_helpers() {
        let c = Crypto::new(&[1u8; 32]);
        let a = c.public_key().to_owned();
        let b = Crypto::new(&[2u8; 32]).public_key().to_owned();
        assert_eq!(public_key_less(&a, &b), a.as_bytes() < b.as_bytes());
        assert_eq!(public_key_addr(a).as_key(), &a);
        let sig = c.sign(b"msg");
        assert!(public_key_verify(&a, b"msg", &sig));
        assert!(!public_key_verify(&a, b"other", &sig));
    }

    #[test]
    fn rejects_invalid_public_keys() {
        // Векторы из ironwood/types/crypto_test.go.
        let invalid = [
            "0200000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ];
        for encoded in invalid {
            let bytes = hex_bytes(encoded);
            assert!(
                !is_public_key_valid(&bytes),
                "key {encoded} must be rejected"
            );
            assert!(public_key_from_bytes(&bytes).is_none());
        }

        let valid = Crypto::new(&[7u8; 32]);
        assert!(is_public_key_valid(valid.public_key().as_bytes()));
        assert_eq!(
            public_key_from_bytes(valid.public_key().as_bytes()).as_ref(),
            Some(valid.public_key())
        );
    }

    fn hex_bytes(encoded: &str) -> [u8; PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).expect("hex");
        }
        bytes
    }

    #[test]
    fn private_key_expanded_is_go_layout() {
        let c = Crypto::new(&[0x42u8; 32]);
        let full = private_key_expanded(c.private_key());
        assert_eq!(&full[..32], &[0x42u8; 32]);
        assert_eq!(&full[32..], c.public_key().as_bytes());
        assert!(private_key_equal(
            c.private_key(),
            &SigningKey::from_bytes(&[0x42u8; 32])
        ));
    }
}
