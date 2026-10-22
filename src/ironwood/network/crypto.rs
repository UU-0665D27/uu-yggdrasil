use crate::ironwood::types::addr::KeyAddr;
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
