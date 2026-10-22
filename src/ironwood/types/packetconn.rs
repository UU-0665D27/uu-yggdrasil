use crate::ironwood::errors::Error;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};

/// Аналог net.Conn с TCP-подобной семантикой (reliable ordered).
/// В tokio std-трейта `net.Conn` нет, поэтому вводим свой alias.
pub trait AsyncConn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncConn for T {}

/// Аналог net.PacketConn.
/// `tokio::net::UdpSocket` — конкретный тип, трейта нет → свой.
/// Закрытие — через Drop сокета, отдельного `close()` не нужно.
#[async_trait::async_trait]
pub trait PacketConnBase: Send + Sync {
    /// Принимает одну датаграмму в `buf` и возвращает её длину и адрес отправителя.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ввода-вывода, если сокет закрыт, дедлайн истёк
    /// или чтение завершилось неудачей.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Отправляет `buf` на `addr` и возвращает число записанных байт.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ввода-вывода, если сокет закрыт, дедлайн истёк
    /// или запись завершилась неудачей.
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;

    /// Возвращает локальный адрес, к которому привязан сокет.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если базовый сокет закрыт или адрес недоступен.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait::async_trait]
pub trait PacketConn: PacketConnBase {
    /// Блокируется (await'ится), пока `conn` используется.
    /// Завершается почти сразу после вызова `close()` на `PacketConn`.
    /// `conn` закрывается до возврата — владение передаётся внутрь,
    /// Drop закроет сокет.
    ///
    /// # Errors
    ///
    /// Возвращает:
    /// - [`Error::CLOSED`] — если `PacketConn` был закрыт во время работы сессии;
    /// - ошибку протокола/кодирования (см. варианты [`Error`]) при сбое обработки;
    /// - ошибку ввода-вывода, если `conn` вернул её до штатного завершения.
    async fn handle_conn(
        &self,
        key: &VerifyingKey,
        conn: Box<dyn AsyncConn>,
        prio: u8,
    ) -> Result<(), Error>;

    /// `true` ⇔ соединение закрыто. Не блокируется, не await'ится.
    /// Обычно `AtomicBool` внутри.
    fn is_closed(&self) -> bool;

    /// Возвращает `Arc`, чтобы избежать клонирования секрета на каждый вызов.
    fn private_key(&self) -> Arc<SigningKey>;

    /// MTU (максимальный безопасный размер сообщения).
    fn mtu(&self) -> u64;

    /// Отправить lookup по (возможно частичному) ключу.
    /// Если внутри нужен await (например, `send_to`) — сделайте его `async fn`.
    fn send_lookup(&self, target: &VerifyingKey);
}
