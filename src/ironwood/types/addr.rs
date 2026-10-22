use ed25519_dalek::VerifyingKey;
use std::fmt;

/// Аналог `net.Addr`. `Display` заменяет `String()`,
/// `network()` — `Network()`.
pub trait Addr: fmt::Debug + fmt::Display + Send + Sync {
    fn network(&self) -> &'static str;
}

/// Аналог `types.Addr ed25519.PublicKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyAddr(pub VerifyingKey);

impl KeyAddr {
    pub const NETWORK: &'static str = "ed25519.PublicKey";

    #[must_use]
    pub const fn new(key: VerifyingKey) -> Self {
        Self(key)
    }
    #[must_use]
    pub const fn as_key(&self) -> &VerifyingKey {
        &self.0
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for KeyAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Аналог hex.EncodeToString(a), без аллокации String.
        for b in self.0.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Addr for KeyAddr {
    fn network(&self) -> &'static str {
        Self::NETWORK
    }
}
