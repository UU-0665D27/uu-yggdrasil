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
impl crate::ironwood::network::packet_queue::PqPacket for Traffic {
    fn wire_type(&self) -> crate::ironwood::network::wire::WirePacketType {
        crate::ironwood::network::wire::WirePacketType::Traffic
    }

    fn source_key(&self) -> crate::ironwood::network::crypto::PublicKey {
        self.source
    }

    fn dest_key(&self) -> crate::ironwood::network::crypto::PublicKey {
        self.dest
    }
}

impl Traffic {
    #[must_use]
    pub const fn wire_type() -> WirePacketType {
        WirePacketType::Traffic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(b: u8) -> PublicKey {
        SigningKey::from_bytes(&[b; 32]).verifying_key()
    }

    fn sample() -> Traffic {
        Traffic {
            path: vec![1, 300, u64::MAX],
            from: vec![7],
            source: key(1),
            dest: key(2),
            watermark: u64::MAX,
            payload: b"hello".to_vec(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let tr = sample();
        let mut out = Vec::new();
        tr.encode(&mut out).expect("encode");
        assert_eq!(out.len(), WireEncodable::size(&tr));
        let got = Traffic::decode(&out).expect("decode");
        assert_eq!(got.path, tr.path);
        assert_eq!(got.from, tr.from);
        assert_eq!(got.source, tr.source);
        assert_eq!(got.dest, tr.dest);
        assert_eq!(got.watermark, tr.watermark);
        assert_eq!(got.payload, tr.payload);
    }

    #[test]
    fn empty_payload_and_paths() {
        let tr = Traffic {
            path: vec![],
            from: vec![],
            source: key(3),
            dest: key(4),
            watermark: 0,
            payload: vec![],
        };
        let mut out = Vec::new();
        tr.encode(&mut out).expect("encode");
        let got = Traffic::decode(&out).expect("decode");
        assert!(got.payload.is_empty());
        assert!(got.path.is_empty());
        assert!(got.from.is_empty());
    }

    #[test]
    fn header_size_matches_empty() {
        let tr = Traffic {
            path: vec![],
            from: vec![],
            source: key(0),
            dest: key(0),
            watermark: u64::MAX,
            payload: vec![],
        };
        assert_eq!(Traffic::header_size(), WireEncodable::size(&tr) as u64 + 1);
    }

    #[test]
    fn decode_rejects_truncated() {
        let tr = sample();
        let mut out = Vec::new();
        tr.encode(&mut out).expect("encode");
        for cut in 0..(out.len() - tr.payload.len()) {
            assert!(Traffic::decode(&out[..cut]).is_err(), "cut={cut}");
        }
        // Обрезанный payload — это уже просто более короткий payload.
        let got = Traffic::decode(&out[..out.len() - 1]).expect("header intact");
        assert_eq!(got.payload, b"hell");
    }

    #[test]
    fn decode_keeps_trailing_bytes_as_payload() {
        let tr = sample();
        let mut out = Vec::new();
        tr.encode(&mut out).expect("encode");
        out.extend_from_slice(&[0xde, 0xad]);
        let got = Traffic::decode(&out).expect("decode");
        assert_eq!(got.payload, b"hello\xde\xad");
    }
}
