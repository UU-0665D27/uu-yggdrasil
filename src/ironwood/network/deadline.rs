use std::sync::{Mutex, PoisonError};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Аналог `type deadline struct` из `packetconn.go`.
///
/// Хранит текущий `CancellationToken` — он отменяется таймером или `set`.
/// Повторный `set` с `None` снимает дедлайн. Просроченный токен заменяется
/// при следующем `set`, чтобы новые `cancelled()` не просыпались мгновенно.
pub struct Deadline {
    inner: Mutex<Inner>,
}

struct Inner {
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Deadline {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                cancel: CancellationToken::new(),
                task: None,
            }),
        }
    }

    /// `func (d *deadline) set(t time.Time)`. `None` = без дедлайна.
    ///
    /// Poison от предыдущей паники восстанавливается: состояние `Inner`
    /// (токен и `JoinHandle`) остаётся валидным, отменять нечего.
    pub fn set(&self, t: Option<Instant>) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);

        if let Some(task) = inner.task.take() {
            task.abort();
        }

        if inner.cancel.is_cancelled() {
            inner.cancel = CancellationToken::new();
        }

        if let Some(t) = t {
            let token = inner.cancel.clone();
            inner.task = Some(tokio::spawn(async move {
                tokio::time::sleep_until(t).await;
                token.cancel();
            }));
        }
    }

    /// Ждать отмены текущего дедлайна. Аналог `<-d.getCancel()`.
    pub async fn cancelled(&self) {
        let token = {
            let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            inner.cancel.clone()
        };
        token.cancelled().await;
    }
}

impl Default for Deadline {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(task) = inner.task.take()
        {
            task.abort();
        }
    }
}
