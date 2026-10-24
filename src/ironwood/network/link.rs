//! Link-слой yggdrasil v0.5: `meta`-handshake поверх надёжного потока
//! (TCP/WS/TLS/QUIC/Unix).
//!
//! Формат: `"meta" | len:u16be | fields | sig:64`, где
//! `fields` — повторяющиеся `(op:u16be, len:u16be, value)`:
//! `0=major:u16`, `1=minor:u16`, `2=publicKey:[32]`, `3=priority:u8`.
//! `sig` — Ed25519-подпись `blake2b-512(key=password, data=publicKey)`.
//!
//! Работает через `Read`/`Write`, поэтому handshake можно гонять
//! на массиве байт (фаззинг) и на `TcpStream` через `SyncIoBridge`.

use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2b512, Blake2bMac512};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::io::{self, Read, Write};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `ProtocolVersionMajor` из yggdrasil-go.
pub const LINK_VERSION_MAJOR: u16 = 0;
/// `ProtocolVersionMinor` из yggdrasil-go.
pub const LINK_VERSION_MINOR: u16 = 5;

/// `metaVersionMajor` и т.д.
const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

/// 4 байта `"meta"` + 2 байта длины.
pub const META_HEADER_SIZE: usize = 6;
/// Разумный предел на метаданные (реальный пакет ~125 байт).
pub const META_MAX_SIZE: usize = 4096;
const SIG_SIZE: usize = 64;

/// Разобранный `meta` удалённой стороны.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkMeta {
    pub major: u16,
    pub minor: u16,
    pub public_key: VerifyingKey,
    pub priority: u8,
}

impl LinkMeta {
    /// Совместимость по версии (как `version_metadata.check()` в Go).
    #[must_use]
    pub const fn is_compatible(&self) -> bool {
        self.major == LINK_VERSION_MAJOR && self.minor == LINK_VERSION_MINOR
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn hash_public_key(password: &[u8], key: &VerifyingKey) -> io::Result<[u8; 64]> {
    if password.len() > 64 {
        return Err(invalid("password is too long for blake2b key"));
    }
    if password.is_empty() {
        // Go: blake2b.New512(nil) — неключевой режим.
        let mut hasher = Blake2b512::new();
        hasher.update(key.as_bytes());
        return Ok(hasher.finalize().into());
    }
    let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(password)
        .map_err(|_| invalid("password is too long for blake2b key"))?;
    mac.update(key.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Собрать `meta` для отправки. `password` — общий пароль (может быть пустым).
///
/// # Errors
/// Только если пароль длиннее 64 байт (ограничение `BLAKE2b`).
pub fn encode_meta(secret: &SigningKey, password: &[u8], priority: u8) -> io::Result<Vec<u8>> {
    let public = secret.verifying_key();
    let mut out = Vec::with_capacity(META_HEADER_SIZE + 120);
    out.extend_from_slice(b"meta");
    out.extend_from_slice(&[0, 0]); // длина, заполним в конце

    put_u16(&mut out, META_VERSION_MAJOR);
    put_u16(&mut out, 2);
    put_u16(&mut out, LINK_VERSION_MAJOR);

    put_u16(&mut out, META_VERSION_MINOR);
    put_u16(&mut out, 2);
    put_u16(&mut out, LINK_VERSION_MINOR);

    put_u16(&mut out, META_PUBLIC_KEY);
    put_u16(&mut out, 32);
    out.extend_from_slice(public.as_bytes());

    put_u16(&mut out, META_PRIORITY);
    put_u16(&mut out, 1);
    out.push(priority);

    let hash = hash_public_key(password, &public)?;
    out.extend_from_slice(&secret.sign(&hash).to_bytes());

    let len =
        u16::try_from(out.len() - META_HEADER_SIZE).map_err(|_| invalid("meta is too long"))?;
    out[4..6].copy_from_slice(&len.to_be_bytes());
    Ok(out)
}

/// Разобрать `meta` из полного буфера (для тестов/фаззинга).
///
/// # Errors
/// Битая длина/преамбула/версия/подпись.
pub fn decode_meta(data: &[u8], password: &[u8]) -> io::Result<LinkMeta> {
    if data.len() < META_HEADER_SIZE {
        return Err(invalid("short meta header"));
    }
    if &data[..4] != b"meta" {
        return Err(invalid("invalid preamble"));
    }
    let len = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if len < SIG_SIZE || data.len() != META_HEADER_SIZE + len {
        return Err(invalid("invalid meta length"));
    }

    let raw = &data[META_HEADER_SIZE..];
    let (fields, sig_bytes) = raw.split_at(raw.len() - SIG_SIZE);

    let mut major = None;
    let mut minor = None;
    let mut public_key = None;
    let mut priority = 0u8;

    let mut rest = fields;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(invalid("truncated meta field"));
        }
        let op = u16::from_be_bytes([rest[0], rest[1]]);
        let flen = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        rest = &rest[4..];
        if rest.len() < flen {
            return Err(invalid("truncated meta field value"));
        }
        let value = &rest[..flen];
        rest = &rest[flen..];

        match op {
            META_VERSION_MAJOR => {
                if flen != 2 {
                    return Err(invalid("bad major version length"));
                }
                major = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            META_VERSION_MINOR => {
                if flen != 2 {
                    return Err(invalid("bad minor version length"));
                }
                minor = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            META_PUBLIC_KEY => {
                if flen != 32 {
                    return Err(invalid("bad public key length"));
                }
                let mut kb = [0u8; 32];
                kb.copy_from_slice(value);
                public_key =
                    Some(VerifyingKey::from_bytes(&kb).map_err(|_| invalid("bad public key"))?);
            }
            META_PRIORITY => {
                if flen != 1 {
                    return Err(invalid("bad priority length"));
                }
                priority = value[0];
            }
            _ => {} // неизвестные поля игнорируем, как Go
        }
    }

    let public_key = public_key.ok_or_else(|| invalid("missing public key"))?;

    let mut sb = [0u8; SIG_SIZE];
    sb.copy_from_slice(sig_bytes);
    let sig = Signature::from_bytes(&sb);
    let hash = hash_public_key(password, &public_key)?;
    public_key
        .verify_strict(&hash, &sig)
        .map_err(|_| invalid("incorrect password or signature"))?;

    let major = major.ok_or_else(|| invalid("missing major version"))?;
    let minor = minor.ok_or_else(|| invalid("missing minor version"))?;
    Ok(LinkMeta {
        major,
        minor,
        public_key,
        priority,
    })
}

/// Записать `meta` в поток.
///
/// # Errors
/// Ошибки `Write` или слишком длинный пароль.
pub fn write_meta<W: Write + ?Sized>(
    w: &mut W,
    secret: &SigningKey,
    password: &[u8],
    priority: u8,
) -> io::Result<()> {
    let bs = encode_meta(secret, password, priority)?;
    w.write_all(&bs)
}

/// Прочитать `meta` из потока.
///
/// # Errors
/// EOF, неверная длина, битая подпись.
pub fn read_meta<R: Read + ?Sized>(r: &mut R, password: &[u8]) -> io::Result<LinkMeta> {
    let mut header = [0u8; META_HEADER_SIZE];
    r.read_exact(&mut header)?;
    if &header[..4] != b"meta" {
        return Err(invalid("invalid preamble"));
    }
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if !(SIG_SIZE..=META_MAX_SIZE).contains(&len) {
        return Err(invalid("invalid meta length"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;

    let mut full = Vec::with_capacity(META_HEADER_SIZE + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    decode_meta(&full, password)
}

/// Асинхронный `read_meta`.
///
/// # Errors
/// См. [`read_meta`].
pub async fn read_meta_async<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    password: &[u8],
) -> io::Result<LinkMeta> {
    let mut header = [0u8; META_HEADER_SIZE];
    r.read_exact(&mut header).await?;
    if &header[..4] != b"meta" {
        return Err(invalid("invalid preamble"));
    }
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if !(SIG_SIZE..=META_MAX_SIZE).contains(&len) {
        return Err(invalid("invalid meta length"));
    }
    let mut full = vec![0u8; META_HEADER_SIZE + len];
    full[..META_HEADER_SIZE].copy_from_slice(&header);
    r.read_exact(&mut full[META_HEADER_SIZE..]).await?;
    decode_meta(&full, password)
}

/// Асинхронный `write_meta`.
///
/// # Errors
/// См. [`write_meta`].
pub async fn write_meta_async<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    secret: &SigningKey,
    password: &[u8],
    priority: u8,
) -> io::Result<()> {
    let bs = encode_meta(secret, password, priority)?;
    w.write_all(&bs).await?;
    w.flush().await
}

/// Симметричный handshake: отправить свой `meta`, прочитать чужой.
/// Обе стороны yggdrasil вызывают его в одном порядке (write → read).
///
/// # Errors
/// Ошибки ввода-вывода, несовместимая версия, неверный пароль.
pub async fn handshake_async<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    secret: &SigningKey,
    password: &[u8],
    priority: u8,
) -> io::Result<LinkMeta> {
    write_meta_async(stream, secret, password, priority).await?;
    let meta = read_meta_async(stream, password).await?;
    if !meta.is_compatible() {
        return Err(invalid("incompatible yggdrasil protocol version"));
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sk = key(1);
        let bs = encode_meta(&sk, b"", 7).expect("encode");
        assert_eq!(&bs[..4], b"meta");
        let meta = decode_meta(&bs, b"").expect("decode");
        assert_eq!(meta.public_key, sk.verifying_key());
        assert_eq!(meta.priority, 7);
        assert_eq!(meta.major, 0);
        assert_eq!(meta.minor, 5);
        assert!(meta.is_compatible());
    }

    #[test]
    fn password_must_match() {
        let sk = key(2);
        let bs = encode_meta(&sk, b"shared", 0).expect("encode");
        assert!(decode_meta(&bs, b"").is_err());
        assert!(decode_meta(&bs, b"wrong").is_err());
        assert!(decode_meta(&bs, b"shared").is_ok());
    }

    #[test]
    fn tampering_is_rejected() {
        let sk = key(3);
        let bs = encode_meta(&sk, b"", 0).expect("encode");
        // publicKey (22..54) и подпись входят в аутентифицируемые данные.
        for i in 22..54 {
            let mut bad = bs.clone();
            bad[i] ^= 0x01;
            assert!(decode_meta(&bad, b"").is_err(), "pubkey byte {i}");
        }
        for i in (bs.len() - 64)..bs.len() {
            let mut bad = bs.clone();
            bad[i] ^= 0x01;
            assert!(decode_meta(&bad, b"").is_err(), "sig byte {i}");
        }
        // Версия и priority в Go не подписаны: меняются, но не ломают подпись.
        let mut bad = bs;
        bad[11] = 9; // major value low byte
        let meta = decode_meta(&bad, b"").expect("version is not signed");
        assert!(!meta.is_compatible());
    }

    #[test]
    fn read_write_stream() {
        let sk = key(4);
        let mut buf = Vec::new();
        write_meta(&mut buf, &sk, b"pw", 3).expect("write");
        let mut cursor = buf.as_slice();
        let meta = read_meta(&mut cursor, b"pw").expect("read");
        assert_eq!(meta.public_key, sk.verifying_key());
        assert_eq!(cursor, &[] as &[u8]);
    }

    #[test]
    fn rejects_bad_lengths() {
        let sk = key(5);
        let bs = encode_meta(&sk, b"", 0).expect("encode");
        assert!(decode_meta(&bs[..5], b"").is_err());
        assert!(decode_meta(&bs[..bs.len() - 1], b"").is_err());
        assert!(decode_meta(&[&b"meta"[..], &[0xff, 0xff][..]].concat(), b"").is_err());

        let mut bad = bs;
        bad[4] = 0;
        bad[5] = 10; // меньше подписи
        assert!(decode_meta(&bad, b"").is_err());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let sk = key(6);
        let mut bs = encode_meta(&sk, b"", 0).expect("encode");
        // Пересобрать вручную с лишним полем перед подписью.
        let raw_len = bs.len() - META_HEADER_SIZE - SIG_SIZE;
        let sig = bs.split_off(META_HEADER_SIZE + raw_len);
        bs.extend_from_slice(&[0x00, 0x63, 0x00, 0x02, 0xde, 0xad]);
        bs.extend_from_slice(&sig);
        let len = u16::try_from(bs.len() - META_HEADER_SIZE).expect("len");
        bs[4..6].copy_from_slice(&len.to_be_bytes());
        // Подпись считается только по publicKey, так что остаётся валидной.
        assert!(decode_meta(&bs, b"").is_ok());
    }
}

#[cfg(test)]
mod golden {
    use super::*;

    // Сгенерировано yggdrasil-go: seed=[7;32], password="", priority=0.
    const META: &str = "6d657461007500000002000000010002000500020020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0003000100e53968d8306c04d5b022c8494b24898ed98e22e28d2decaa44c25bda6cebaeac110a473e7ebe0a8aef210fe21e3b001d66e94d55c84c6a91deaa2c6dce09270c";

    // seed=[8;32], password="shared", priority=3.
    const META_PW: &str = "6d6574610075000000020000000100020005000200201398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca0003000103bd9ecc6ff90845c74709d6e39438238fcf769652179f137bc15a6bd6e1881a457b2eb5616b6ac6499f6cd07007a2b6efcd3ff7d37ac534be0e6cbdfe3a024a06";

    #[test]
    fn keyed_encode_matches_yggdrasil_go() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let bs = encode_meta(&sk, b"shared", 3).expect("encode");
        let hex: String = bs.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, META_PW);
        assert!(decode_meta(&bs, b"shared").is_ok());
    }

    #[test]
    fn encode_matches_yggdrasil_go() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = (0..META.len() / 2)
            .map(|i| u8::from_str_radix(&META[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect::<Vec<_>>();
        assert!(decode_meta(&bytes, b"").is_ok(), "golden must verify");

        let bs = encode_meta(&sk, b"", 0).expect("encode");
        let hex: String = bs.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, META);
        assert!(decode_meta(&bs, b"").is_ok());
    }
}
