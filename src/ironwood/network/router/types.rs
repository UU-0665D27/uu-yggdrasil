use ed25519_dalek::Signature;

use crate::ironwood::{
    errors::Error,
    network::{
        crypto::{PublicKey, SIGNATURE_SIZE, public_key_verify},
        wire::{
            PeerPort, WireEncodable, wire_append_uint, wire_chop_slice, wire_chop_uint,
            wire_size_uint,
        },
    },
};

/// `routerSigReq { seq, nonce }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterSigReq {
    pub seq: u64,
    pub nonce: u64,
}

impl RouterSigReq {
    /// `node || parent || seq(varint) || nonce(varint)`.
    #[must_use]
    pub fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 20);
        out.extend_from_slice(node.as_bytes());
        out.extend_from_slice(parent.as_bytes());
        wire_append_uint(&mut out, self.seq);
        wire_append_uint(&mut out, self.nonce);
        out
    }

    /// Читает req, оставляет хвост в `data`.
    ///
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn chop(data: &mut &[u8]) -> Result<Self, Error> {
        let seq = wire_chop_uint(data).ok_or(Error::DECODE)?;
        let nonce = wire_chop_uint(data).ok_or(Error::DECODE)?;
        Ok(Self { seq, nonce })
    }

    /// # Errors
    /// [`Error::DECODE`] если байт не хватает или остаток не пустой.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let req = Self::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(req)
    }
}

impl WireEncodable for RouterSigReq {
    fn size(&self) -> usize {
        wire_size_uint(self.seq) + wire_size_uint(self.nonce)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire_append_uint(out, self.seq);
        wire_append_uint(out, self.nonce);
        Ok(())
    }
}

/// `routerSigRes { req, port, psig }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterSigRes {
    pub req: RouterSigReq,
    pub port: PeerPort,
    pub psig: Signature,
}

impl RouterSigRes {
    /// `node || parent || req || port(varint)` — то, что подписывает `parent`.
    #[must_use]
    pub fn bytes_for_sig(&self, node: &PublicKey, parent: &PublicKey) -> Vec<u8> {
        let mut out = self.req.bytes_for_sig(node, parent);
        wire_append_uint(&mut out, self.port);
        out
    }

    /// Проверка подписи `psig` под `bytes_for_sig(node, parent)` ключом `parent`.
    #[must_use]
    pub fn check(&self, node: &PublicKey, parent: &PublicKey) -> bool {
        if self.port == 0 && node != parent {
            return false;
        }
        public_key_verify(parent, &self.bytes_for_sig(node, parent), &self.psig)
    }

    /// Читает res, оставляет хвост в `data`.
    ///
    /// # Errors
    /// [`Error::DECODE`] при нехватке или повреждении байт.
    pub fn chop(data: &mut &[u8]) -> Result<Self, Error> {
        let req = RouterSigReq::chop(data)?;
        let port = wire_chop_uint(data).ok_or(Error::DECODE)?;
        let mut psig_bytes = [0u8; SIGNATURE_SIZE];
        if !wire_chop_slice(&mut psig_bytes, data) {
            return Err(Error::DECODE);
        }
        Ok(Self {
            req,
            port,
            psig: Signature::from_bytes(&psig_bytes),
        })
    }

    /// # Errors
    /// [`Error::DECODE`] если байт не хватает или остаток не пустой.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;
        let res = Self::chop(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }
        Ok(res)
    }
}

impl WireEncodable for RouterSigRes {
    fn size(&self) -> usize {
        self.req.size() + wire_size_uint(self.port) + SIGNATURE_SIZE
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.req.encode(out)?;
        wire_append_uint(out, self.port);
        out.extend_from_slice(&self.psig.to_bytes());
        Ok(())
    }
}

/// `routerAnnounce { key, parent, res, sig }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterAnnounce {
    pub key: PublicKey,
    pub parent: PublicKey,
    pub res: RouterSigRes,
    pub sig: Signature,
}

impl RouterAnnounce {
    /// `res.bytes_for_sig(key, parent)`.
    #[must_use]
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        self.res.bytes_for_sig(&self.key, &self.parent)
    }

    /// `sig` ключом `key` и `psig` ключом `parent` от одного `bytes_for_sig()`.
    #[must_use]
    pub fn check(&self) -> bool {
        if self.res.port == 0 && self.key != self.parent {
            return false;
        }
        let bs = self.bytes_for_sig();
        public_key_verify(&self.key, &bs, &self.sig)
            && public_key_verify(&self.parent, &bs, &self.res.psig)
    }

    /// # Errors
    /// [`Error::DECODE`] если байт не хватает или остаток не пустой.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut rest = data;

        let mut key_bytes = [0u8; 32];
        if !wire_chop_slice(&mut key_bytes, &mut rest) {
            return Err(Error::DECODE);
        }
        let mut parent_bytes = [0u8; 32];
        if !wire_chop_slice(&mut parent_bytes, &mut rest) {
            return Err(Error::DECODE);
        }

        let key = PublicKey::from_bytes(&key_bytes).map_err(|_| Error::DECODE)?;
        let parent = PublicKey::from_bytes(&parent_bytes).map_err(|_| Error::DECODE)?;

        let res = RouterSigRes::chop(&mut rest)?;

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        if !wire_chop_slice(&mut sig_bytes, &mut rest) {
            return Err(Error::DECODE);
        }
        if !rest.is_empty() {
            return Err(Error::DECODE);
        }

        Ok(Self {
            key,
            parent,
            res,
            sig: Signature::from_bytes(&sig_bytes),
        })
    }
}

impl WireEncodable for RouterAnnounce {
    fn size(&self) -> usize {
        32 + 32 + self.res.size() + SIGNATURE_SIZE
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(self.parent.as_bytes());
        self.res.encode(out)?;
        out.extend_from_slice(&self.sig.to_bytes());
        Ok(())
    }
}

/// `routerInfo` — значение в `infos: HashMap<PublicKey, RouterInfo>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterInfo {
    pub parent: PublicKey,
    pub res: RouterSigRes,
    pub sig: Signature,
}

impl RouterInfo {
    #[must_use]
    pub fn get_announce(&self, key: PublicKey) -> RouterAnnounce {
        RouterAnnounce {
            key,
            parent: self.parent,
            res: self.res,
            sig: self.sig,
        }
    }
}
