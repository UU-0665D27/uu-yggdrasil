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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn display_is_lowercase_hex() {
        let k = SigningKey::from_bytes(&[0xabu8; 32]).verifying_key();
        let a = KeyAddr::new(k);
        let expected = k.as_bytes().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(a.to_string(), expected);
        assert_eq!(a.to_string().len(), 64);
        assert_eq!(a.as_bytes(), k.as_bytes());
        assert_eq!(a.as_key(), &k);
    }

    #[test]
    fn network_name_matches_go() {
        let k = SigningKey::from_bytes(&[0u8; 32]).verifying_key();
        assert_eq!(KeyAddr::new(k).network(), "ed25519.PublicKey");
        assert_eq!(format!("{:?}", KeyAddr::new(k)), format!("KeyAddr({k:?})"));
    }
}
