use ed25519_dalek::VerifyingKey;
use std::{sync::Arc, time::Duration};

/// 1 MiB.
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1_048_576;

/// `func(ed25519.PublicKey) ed25519.PublicKey`.
pub type BloomTransform = Arc<dyn Fn(&VerifyingKey) -> VerifyingKey + Send + Sync>;

/// `func(ed25519.PublicKey)`.
pub type PathNotify = Arc<dyn Fn(&VerifyingKey) + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub router_refresh: Duration,
    pub router_timeout: Duration,
    pub peer_keep_alive_delay: Duration,
    pub peer_timeout: Duration,
    pub peer_max_message_size: u64,
    pub bloom_transform: BloomTransform,
    pub path_notify: PathNotify,
    pub path_timeout: Duration,
    pub path_throttle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            router_refresh: Duration::from_mins(4),
            router_timeout: Duration::from_mins(5),
            peer_keep_alive_delay: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            peer_max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            bloom_transform: Arc::new(|k| *k),
            path_notify: Arc::new(|_| {}),
            path_timeout: Duration::from_secs(60),
            path_throttle: Duration::from_secs(1),
        }
    }
}

impl Config {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_router_refresh(mut self, d: Duration) -> Self {
        self.router_refresh = d;
        self
    }
    #[must_use]
    pub const fn with_router_timeout(mut self, d: Duration) -> Self {
        self.router_timeout = d;
        self
    }
    #[must_use]
    pub const fn with_peer_keep_alive_delay(mut self, d: Duration) -> Self {
        self.peer_keep_alive_delay = d;
        self
    }
    #[must_use]
    pub const fn with_peer_timeout(mut self, d: Duration) -> Self {
        self.peer_timeout = d;
        self
    }
    #[must_use]
    pub const fn with_peer_max_message_size(mut self, size: u64) -> Self {
        self.peer_max_message_size = size;
        self
    }
    #[must_use]
    pub fn with_bloom_transform<F>(mut self, f: F) -> Self
    where
        F: Fn(&VerifyingKey) -> VerifyingKey + Send + Sync + 'static,
    {
        self.bloom_transform = Arc::new(f);
        self
    }
    #[must_use]
    pub fn with_path_notify<F>(mut self, f: F) -> Self
    where
        F: Fn(&VerifyingKey) + Send + Sync + 'static,
    {
        self.path_notify = Arc::new(f);
        self
    }
    #[must_use]
    pub const fn with_path_timeout(mut self, d: Duration) -> Self {
        self.path_timeout = d;
        self
    }
    #[must_use]
    pub const fn with_path_throttle(mut self, d: Duration) -> Self {
        self.path_throttle = d;
        self
    }
}
