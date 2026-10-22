use crate::ironwood::{
    errors::Error,
    network::{
        crypto::PublicKey,
        wire::{
            PeerPort, WireEncodable, WirePacketType, wire_append_path, wire_append_uint,
            wire_chop_path, wire_chop_slice, wire_chop_uint, wire_size_path, wire_size_uint,
        },
    },
};

/// Аналог `type traffic struct`.
/// wire: path || from || source(32) || dest(32) || watermark(varint) || payload.
#[derive(Debug, Clone)]
pub struct Traffic {
    pub path: Vec<PeerPort>,
    pub from: Vec<PeerPort>,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub watermark: u64,
    pub payload: Vec<u8>,
}

impl Traffic {
    /// Размер заголовка для пустого `Traffic` (payload = 0, watermark = `u64::MAX`),
    /// плюс байт типа сообщения — аналог `overhead := uint64(tr.size()) + 1`
    /// в Go-шном `PacketConn.MTU()`.
    #[must_use]
    pub const fn header_size() -> u64 {
        // path terminator (1) + from terminator (1)
        // + source (32) + dest (32)
        // + watermark varint для u64::MAX (10)
        // + type byte (1)
        // = 77
        1 + 1 + 32 + 32 + 10 + 1
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.size_usize() as u64
    }

    fn size_usize(&self) -> usize {
        wire_size_path(&self.path)
            + wire_size_path(&self.from)
            + 32
            + 32
            + wire_size_uint(self.watermark)
            + self.payload.len()
    }

    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;

        let mut path = Vec::new();
        if !wire_chop_path(&mut path, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut from = Vec::new();
        if !wire_chop_path(&mut from, &mut rest) {
            return Err(Error::DECODE);
        }

        let mut source = [0u8; 32];
        if !wire_chop_slice(&mut source, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut dest = [0u8; 32];
        if !wire_chop_slice(&mut dest, &mut rest) {
            return Err(Error::DECODE);
        }

        let watermark = wire_chop_uint(&mut rest).ok_or(Error::DECODE)?;

        let source = PublicKey::from_bytes(&source).map_err(|_| Error::DECODE)?;
        let dest = PublicKey::from_bytes(&dest).map_err(|_| Error::DECODE)?;

        Ok(Self {
            path,
            from,
            source,
            dest,
            watermark,
            payload: rest.to_vec(),
        })
    }
}

impl WireEncodable for Traffic {
    fn size(&self) -> usize {
        self.size_usize()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_path(out, &self.path);
        wire_append_path(out, &self.from);
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        wire_append_uint(out, self.watermark);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Traffic {
    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::Traffic
    }
}
