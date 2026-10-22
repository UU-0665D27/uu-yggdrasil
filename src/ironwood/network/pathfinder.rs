//! Wire-сообщения pathfinder'а: `PathLookup`, PathNotify(+Info), `PathBroken`.
//! Формат Go-совместим. Сами алгоритмы pathfinder'а появятся позже,
//! поверх `Router`.

use crate::ironwood::{
    errors::Error,
    network::{
        crypto::{PublicKey, SIGNATURE_SIZE, Signature, public_key_verify},
        wire::{
            PeerPort, WireEncodable, WirePacketType, wire_append_path, wire_append_uint,
            wire_chop_path, wire_chop_slice, wire_chop_uint, wire_size_path, wire_size_uint,
        },
    },
};

/// `pathLookup { source, dest, from }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLookup {
    pub source: PublicKey,
    pub dest: PublicKey,
    pub from: Vec<PeerPort>,
}

impl PathLookup {
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut from = Vec::new();
        if !wire_chop_path(&mut from, &mut rest) {
            return Err(Error::DECODE);
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(Self {
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest: PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?,
            from,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathLookup
    }
}

impl WireEncodable for PathLookup {
    fn size(&self) -> usize {
        32 + 32 + wire_size_path(&self.from)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        wire_append_path(out, &self.from);
        Ok(())
    }
}

/// `pathNotifyInfo { seq, path, sig }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotifyInfo {
    pub seq: u64,
    pub path: Vec<PeerPort>,
    pub sig: Signature,
}

impl PathNotifyInfo {
    /// `seq(varint) || path || sig` — то, что подписывает `source`.
    #[must_use]
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + wire_size_path(&self.path));
        wire_append_uint(&mut out, self.seq);
        wire_append_path(&mut out, &self.path);
        out
    }

    /// `func (info *pathNotifyInfo) equal(cmp)` — сравнить `seq` и `path`,
    /// игнорируя `sig`.
    #[must_use]
    pub fn equal(&self, other: &Self) -> bool {
        self.seq == other.seq && self.path == other.path
    }

    /// Читает info из потока, оставляя хвост в `data`.
    ///
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn chop(data: &mut &[u8]) -> Result<Self, Error> {
        let seq = wire_chop_uint(data).ok_or(Error::DECODE)?;
        let mut path = Vec::new();
        if !wire_chop_path(&mut path, data) {
            return Err(Error::DECODE);
        }
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !wire_chop_slice(&mut sig_bytes, data) {
            return Err(Error::DECODE);
        }
        Ok(Self {
            seq,
            path,
            sig: Signature::from_bytes(&sig_bytes),
        })
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке байт или непустом остатке.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let info = Self::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(info)
    }
}

impl WireEncodable for PathNotifyInfo {
    fn size(&self) -> usize {
        wire_size_uint(self.seq) + wire_size_path(&self.path) + SIGNATURE_SIZE
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_uint(out, self.seq);
        wire_append_path(out, &self.path);
        out.extend_from_slice(&self.sig.to_bytes());
        Ok(())
    }
}

/// `pathNotify { path, watermark, source, dest, info }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotify {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub info: PathNotifyInfo,
}

impl PathNotify {
    /// `func (notify *pathNotify) check()`.
    #[must_use]
    pub fn check(&self) -> bool {
        public_key_verify(&self.source, &self.info.bytes_for_sig(), &self.info.sig)
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;

        let mut path = Vec::new();
        if !wire_chop_path(&mut path, &mut rest) {
            return Err(Error::DECODE);
        }
        let watermark = wire_chop_uint(&mut rest).ok_or(Error::DECODE)?;

        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }

        let info = PathNotifyInfo::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }

        Ok(Self {
            path,
            watermark,
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest: PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?,
            info,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathNotify
    }
}

impl WireEncodable for PathNotify {
    fn size(&self) -> usize {
        wire_size_path(&self.path)
            + wire_size_uint(self.watermark)
            + 32
            + 32
            + WireEncodable::size(&self.info)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_path(out, &self.path);
        wire_append_uint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        self.info.encode(out)
    }
}

/// `pathBroken { path, watermark, source, dest }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBroken {
    pub path: Vec<PeerPort>,
    pub watermark: u64,
    pub source: PublicKey,
    pub dest: PublicKey,
}

impl PathBroken {
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let mut path = Vec::new();
        if !wire_chop_path(&mut path, &mut rest) {
            return Err(Error::DECODE);
        }
        let watermark = wire_chop_uint(&mut rest).ok_or(Error::DECODE)?;
        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(Self {
            path,
            watermark,
            source: PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?,
            dest: PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?,
        })
    }

    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::ProtoPathBroken
    }
}

impl WireEncodable for PathBroken {
    fn size(&self) -> usize {
        wire_size_path(&self.path) + wire_size_uint(self.watermark) + 32 + 32
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_path(out, &self.path);
        wire_append_uint(out, self.watermark);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        Ok(())
    }
}
