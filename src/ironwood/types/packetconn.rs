use crate::ironwood::{errors::Error, types::addr::KeyAddr};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};

/// Аналог `net.Conn` (TCP-like). Только для рантайма — в фаззере не нужен.
pub trait AsyncConn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncConn for T {}

/// Синхронный байтовый поток. Интерфейс sync-ядра протокола и фаззера.
/// `Cursor<Vec<u8>>`, `TcpStream`, `SyncIoBridge<_>` — все подходят.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Аналог `net.PacketConn` (датаграммы, async — для рантайма).
/// Адресация — по ed25519-ключу (`KeyAddr`), как в ironwood Go.
#[async_trait::async_trait]
pub trait PacketConnBase: Send + Sync {
    /// Принимает одну датаграмму в `buf` и возвращает её длину и адрес отправителя.
    ///
    /// # Errors
    /// Ошибка ввода-вывода, если сокет закрыт, дедлайн истёк
    /// или чтение завершилось неудачей.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, KeyAddr)>;

    /// Отправляет `buf` на `addr` и возвращает число записанных байт
    /// (без учёта заголовков транспорта — по смыслу это `buf.len()`).
    ///
    /// # Errors
    /// Ошибка ввода-вывода, если сокет закрыт, дедлайн истёк
    /// или запись завершилась неудачей.
    async fn send_to(&self, buf: &[u8], addr: &KeyAddr) -> io::Result<usize>;

    /// Возвращает локальный адрес, к которому привязан сокет.
    ///
    /// # Errors
    /// Ошибка, если базовый сокет закрыт или адрес недоступен.
    fn local_addr(&self) -> io::Result<KeyAddr>;

    /// # Errors
    /// [`Error::CLOSED`] при повторном вызове.
    fn close(&self) -> Result<(), Error>;

    /// # Errors
    /// Ошибка установки дедлайна.
    fn set_read_deadline(&self, t: Option<Instant>) -> Result<(), Error>;

    /// # Errors
    /// Ошибка установки дедлайна.
    fn set_write_deadline(&self, t: Option<Instant>) -> Result<(), Error>;

    /// # Errors
    /// Ошибка установки дедлайна.
    fn set_deadline(&self, t: Option<Instant>) -> Result<(), Error> {
        self.set_read_deadline(t)?;
        self.set_write_deadline(t)
    }
}

/// Синхронное ядро протокола. Именно его фаззим.
pub trait PacketConn: PacketConnBase {
    /// Обрабатывает одно TCP-подобное соединение до EOF или ошибки.
    /// Блокирующая, синхронная — можно гонять без tokio-рантайма.
    ///
    /// # Errors
    /// - [`Error::CLOSED`] — если `PacketConn` закрыт во время работы;
    /// - варианты [`Error`] при сбое протокола/кодирования;
    /// - IO-ошибки, если `conn` вернул их до штатного завершения.
    fn handle_conn_sync(
        &self,
        key: &VerifyingKey,
        conn: &mut dyn ReadWrite,
        prio: u8,
    ) -> Result<(), Error>;

    /// `true` ⇔ соединение закрыто. Не блокируется.
    fn is_closed(&self) -> bool;

    /// `Arc`, чтобы не клонировать секрет на каждый вызов.
    fn private_key(&self) -> Arc<SigningKey>;

    /// MTU (максимальный безопасный размер сообщения).
    fn mtu(&self) -> u64;

    /// Отправить lookup по (возможно частичному) ключу.
    fn send_lookup(&self, target: &VerifyingKey);
}

/// Async-обёртка над sync-ядром. Внутри — `spawn_blocking` + `SyncIoBridge`.
///
/// Требует `tokio-util = { version = "0.7", features = ["io-util"] }`.
///
/// # Errors
/// Пробрасывает ошибку из `handle_conn_sync`. Паника внутри протокола
/// не маскируется — она перебрасывается в вызывающий код.
pub async fn handle_conn_async<P>(
    pc: Arc<P>,
    key: VerifyingKey,
    conn: Box<dyn AsyncConn>,
    prio: u8,
) -> Result<(), Error>
where
    P: PacketConn + Send + Sync + 'static + ?Sized,
{
    let joined = tokio::task::spawn_blocking(move || {
        let mut bridge = tokio_util::io::SyncIoBridge::new(conn);
        pc.handle_conn_sync(&key, &mut bridge, prio)
    })
    .await;

    match joined {
        Ok(res) => res,
        // Паника в протоколе — баг, не маскируем:
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Задача отменена (не должна случаться — мы не abort'им).
        Err(_) => Err(Error::CLOSED),
    }
}

// ────────────────────────────────────────────────────────────────────
// Фазз-харнесс. Не часть публичного API.
// ────────────────────────────────────────────────────────────────────
#[doc(hidden)]
pub mod fuzz {
    use crate::ironwood::{
        errors::Error,
        types::{
            addr::KeyAddr,
            packetconn::{PacketConn, PacketConnBase, ReadWrite},
        },
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::time::Instant;

    /// Заглушка. Async-методы `PacketConnBase` возвращают `Err` —
    /// sync-ядро не должно их звать (исходящие датаграммы идут через
    /// внутренний sync-канал, если протокол такой использует).
    pub struct FuzzPacketConn {
        key: Arc<SigningKey>,
        closed: AtomicBool,
    }

    impl FuzzPacketConn {
        #[must_use]
        pub fn new() -> Self {
            Self {
                key: Arc::new(SigningKey::from_bytes(&[0x42u8; 32])),
                closed: AtomicBool::new(false),
            }
        }
    }

    impl Default for FuzzPacketConn {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl PacketConnBase for FuzzPacketConn {
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, KeyAddr)> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "sync path"))
        }
        async fn send_to(&self, _buf: &[u8], _addr: &KeyAddr) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "sync path"))
        }
        fn local_addr(&self) -> io::Result<KeyAddr> {
            Ok(KeyAddr(self.key.verifying_key()))
        }
        fn close(&self) -> Result<(), Error> {
            if self.closed.swap(true, Ordering::SeqCst) {
                return Err(Error::CLOSED);
            }
            Ok(())
        }
        fn set_read_deadline(&self, _t: Option<Instant>) -> Result<(), Error> {
            Ok(())
        }
        fn set_write_deadline(&self, _t: Option<Instant>) -> Result<(), Error> {
            Ok(())
        }
    }

    impl PacketConn for FuzzPacketConn {
        fn handle_conn_sync(
            &self,
            key: &VerifyingKey,
            conn: &mut dyn ReadWrite,
            prio: u8,
        ) -> Result<(), Error> {
            // >>> Подключите сюда реальный протокол: <<<
            //     crate::ironwood::session::run_sync(self, key, conn, prio)
            let _ = (key, conn, prio);
            Ok(())
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
        fn private_key(&self) -> Arc<SigningKey> {
            self.key.clone()
        }
        fn mtu(&self) -> u64 {
            1200
        }
        fn send_lookup(&self, _target: &VerifyingKey) {}
    }

    /// Ввод фаззера: `[key(32) | prio(1) | payload…]`.
    pub fn fuzz_handle_conn(data: &[u8]) {
        if data.len() < 33 {
            return;
        }
        let key_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let prio = data[32];
        let payload = &data[33..];

        let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
            return;
        };

        let pc = FuzzPacketConn::new();
        // `Cursor<Vec<u8>>` реализует и Read, и Write.
        let mut conn = io::Cursor::new(payload.to_vec());
        let _ = pc.handle_conn_sync(&key, &mut conn, prio);
    }
}
