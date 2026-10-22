use crate::ironwood::{
    errors::Error,
    types::{
        addr::KeyAddr,
        packetconn::{PacketConn, PacketConnBase, ReadWrite},
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::{io, sync::Arc};

/// Длина подписи Ed25519 (64 байта).
const SIG_LEN: usize = Signature::BYTE_SIZE;

/// Аналог `signed.PacketConn` из Go.
///
/// Оборачивает базовый `PacketConn`, добавляя к каждому исходящему пакету
/// подпись Ed25519 и проверяя подпись на входящих. Подпись считается от
/// `to_key || msg` (ключ **получателя** + тело), проверка — от
/// `from_key || msg`, где `from_key` берётся из `KeyAddr` отправителя.
/// Это защищает от пересылки чужого сообщения: только тот, кому оно
/// адресовано, увидит валидную подпись.
pub struct SignedPacketConn<P: PacketConn + ?Sized> {
    inner: Arc<P>,
    secret: Arc<SigningKey>,
    public: VerifyingKey,
}

impl<P: PacketConn + ?Sized> SignedPacketConn<P> {
    /// `inner` — уже готовый транспорт (реализация `PacketConn`).
    /// `secret` — секретный ключ этого узла (тот же, что у `inner`).
    #[must_use]
    pub fn new(inner: Arc<P>, secret: SigningKey) -> Self {
        let public = secret.verifying_key();
        Self {
            inner,
            secret: Arc::new(secret),
            public,
        }
    }

    /// `dest = sig || msg`, где `sig = Sign(secret, to_key || msg)`.
    fn sign(&self, to_key: &VerifyingKey, msg: &[u8]) -> Vec<u8> {
        let mut to_sign = Vec::with_capacity(32 + msg.len());
        to_sign.extend_from_slice(to_key.as_bytes());
        to_sign.extend_from_slice(msg);

        let signature = self.secret.sign(&to_sign);

        let mut out = Vec::with_capacity(SIG_LEN + msg.len());
        out.extend_from_slice(&signature.to_bytes());
        out.extend_from_slice(msg);
        out
    }

    /// Проверяет `bs = sig || msg` по ключу отправителя.
    /// Возвращает длину `msg` (смещение всегда `SIG_LEN`), если подпись валидна.
    fn unpack_len(&self, bs: &[u8], from_key: &VerifyingKey) -> Option<usize> {
        if bs.len() < SIG_LEN {
            return None;
        }
        let (sig_bytes, msg) = bs.split_at(SIG_LEN);

        let mut to_verify = Vec::with_capacity(32 + msg.len());
        to_verify.extend_from_slice(self.public.as_bytes());
        to_verify.extend_from_slice(msg);

        let sig_arr: &[u8; SIG_LEN] = sig_bytes.try_into().ok()?;
        let signature = Signature::from_bytes(sig_arr);

        from_key.verify_strict(&to_verify, &signature).ok()?;
        Some(msg.len())
    }
}

#[async_trait::async_trait]
impl<P: PacketConn + Send + Sync + 'static> PacketConnBase for SignedPacketConn<P> {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, KeyAddr)> {
        loop {
            let (n, from) = self.inner.recv_from(buf).await?;

            // Битый/невалидный пакет — молча пропускаем, как в Go.
            let Some(msg_len) = self.unpack_len(&buf[..n], from.as_key()) else {
                continue;
            };

            if msg_len > 0 {
                // Сдвигаем сообщение к началу буфера — аналог copy(p, msg) в Go.
                buf.copy_within(SIG_LEN..SIG_LEN + msg_len, 0);
            }
            return Ok((msg_len, from));
        }
    }

    async fn send_to(&self, buf: &[u8], addr: &KeyAddr) -> io::Result<usize> {
        // `addr` уже `KeyAddr` — проверка типа статическая,
        // ErrBadAddress не нужен (в Go это был type switch).
        let signed = self.sign(addr.as_key(), buf);
        let overhead = signed.len() - buf.len();

        let n = self.inner.send_to(&signed, addr).await?;
        Ok(n.saturating_sub(overhead))
    }

    fn local_addr(&self) -> io::Result<KeyAddr> {
        self.inner.local_addr()
    }
}

impl<P: PacketConn + Send + Sync + 'static> PacketConn for SignedPacketConn<P> {
    fn handle_conn_sync(
        &self,
        key: &VerifyingKey,
        conn: &mut dyn ReadWrite,
        prio: u8,
    ) -> Result<(), Error> {
        self.inner.handle_conn_sync(key, conn, prio)
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn private_key(&self) -> Arc<SigningKey> {
        self.secret.clone()
    }

    fn mtu(&self) -> u64 {
        self.inner.mtu().saturating_sub(SIG_LEN as u64)
    }

    fn send_lookup(&self, target: &VerifyingKey) {
        self.inner.send_lookup(target);
    }
}
#[doc(hidden)]
pub mod fuzz {
    use crate::ironwood::signed::SignedPacketConn;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::sync::Arc;

    /// Фазз-стаб inner — тот же, что в `packetconn::fuzz`,
    /// но здесь нужен только `unpack_len`, поэтому мы просто
    /// создаём `SignedPacketConn` над произвольным `P`.
    pub fn fuzz_unpack(data: &[u8]) {
        if data.len() < 32 {
            return;
        }
        let from_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let bs = &data[32..];

        let Ok(from_key) = VerifyingKey::from_bytes(&from_bytes) else {
            return;
        };

        // Создаём SignedPacketConn с детерминированным ключом
        // (inner не нужен для unpack_len, но требуется по типу).
        let secret = SigningKey::from_bytes(&[0x42u8; 32]);
        let spc = SignedPacketConn::new(
            Arc::new(crate::ironwood::types::packetconn::fuzz::FuzzPacketConn::new()),
            secret,
        );

        // Паника здесь = баг; результат (Some/None) — не паника.
        let _ = spc.unpack_len(bs, &from_key);
    }
}
