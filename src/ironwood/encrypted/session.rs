//! Handshake `encrypted`-слоя: `sessionInit`/`sessionAck`.
//!
//! Формат `sessionInit` (193 байта, `sessionAckSize == sessionInitSize`):
//! `[type:1][fromBoxPub:32][boxed:160]`,
//! где `boxed = XSalsa20Poly1305(key, nonce=0, payload)`, `payload = sig(64) || current(32) || next(32) || keySeq(BE8) || seq(BE8)`.
//!
//! `sig` — Ed25519-подпись от `fromBoxPub || current || next || keySeq || seq`,
//! с `groupAuth.preimage()` в качестве префикса.

use crate::ironwood::encrypted::crypto::{
    BOX_OVERHEAD, BOX_PUB_SIZE, BoxPriv, BoxPub, ED_SIG_SIZE, EdPriv, EdPub, EdSig, GroupAuth,
    box_open, box_seal, ed_check, ed_sign, ed25519_pub_to_curve25519, get_shared, new_box_keys,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `sessionTimeout = time.Minute`.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Минимальный overhead трафика сессии: `[type][lks varint][rks varint][nonce varint][boxOverhead][boxPub]`.
pub const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + BOX_PUB_SIZE;

/// С запасом на 3 u64-varint'а.
pub const SESSION_TRAFFIC_OVERHEAD: usize = SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9;

/// `sessionInitSize = 1 + boxPub + boxOverhead + edSig + boxPub + boxPub + 8 + 8`.
pub const SESSION_INIT_SIZE: usize =
    1 + BOX_PUB_SIZE + BOX_OVERHEAD + ED_SIG_SIZE + BOX_PUB_SIZE + BOX_PUB_SIZE + 8 + 8;

/// `sessionAckSize = sessionInitSize`.
pub const SESSION_ACK_SIZE: usize = SESSION_INIT_SIZE;

/// `sessionTypeDummy`.
pub const SESSION_TYPE_DUMMY: u8 = 0;
/// `sessionTypeInit`.
pub const SESSION_TYPE_INIT: u8 = 1;
/// `sessionTypeAck`.
pub const SESSION_TYPE_ACK: u8 = 2;
/// `sessionTypeTraffic`.
pub const SESSION_TYPE_TRAFFIC: u8 = 3;

/// `type sessionInit struct { current, next, keySeq, seq }`.
#[derive(Debug, Clone)]
pub struct SessionInit {
    pub current: BoxPub,
    pub next: BoxPub,
    pub key_seq: u64,
    pub seq: u64,
}

impl SessionInit {
    /// `newSessionInit(current, next, keySeq)`: `seq = now.Unix()`.
    #[must_use]
    pub fn new(current: BoxPub, next: BoxPub, key_seq: u64) -> Self {
        let seq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            current,
            next,
            key_seq,
            seq,
        }
    }

    /// `func (init *sessionInit) encrypt(from, to, auth) ([]byte, error)`.
    ///
    /// В Go возвращает ошибку только из `to.toBox()`; у нас `VerifyingKey`
    /// уже валиден, поэтому ошибка невозможна — возвращаем `Vec<u8>`.
    #[must_use]
    pub fn encrypt(&self, from: &EdPriv, to: &EdPub, auth: &GroupAuth) -> Vec<u8> {
        let (from_pub, from_priv) = new_box_keys();
        let to_box = ed25519_pub_to_curve25519(to);

        // sigBytes = fromPub || current || next || keySeq(BE8) || seq(BE8)
        let mut sig_bytes = [0u8; 32 + 32 + 32 + 8 + 8];
        sig_bytes[..32].copy_from_slice(&from_pub);
        sig_bytes[32..64].copy_from_slice(&self.current);
        sig_bytes[64..96].copy_from_slice(&self.next);
        sig_bytes[96..104].copy_from_slice(&self.key_seq.to_be_bytes());
        sig_bytes[104..112].copy_from_slice(&self.seq.to_be_bytes());

        let sig = ed_sign(&sig_bytes, from, auth.preimage().map(<[u8; 32]>::as_slice));

        // payload = sig(64) || sigBytes[32..] (= current || next || keySeq || seq)
        let mut payload = [0u8; ED_SIG_SIZE + 80];
        payload[..ED_SIG_SIZE].copy_from_slice(&sig.to_bytes());
        payload[ED_SIG_SIZE..].copy_from_slice(&sig_bytes[32..]);

        let shared = get_shared(&to_box, &from_priv);
        let boxed = box_seal(&shared, &payload, 0);

        let mut data = Vec::with_capacity(SESSION_INIT_SIZE);
        data.push(SESSION_TYPE_INIT);
        data.extend_from_slice(&from_pub);
        data.extend_from_slice(&boxed);
        debug_assert_eq!(data.len(), SESSION_INIT_SIZE);
        data
    }

    /// `func (init *sessionInit) decrypt(priv, from, data, auth) bool`.
    ///
    /// При успехе заполняет `current`, `next`, `key_seq`, `seq`.
    /// `data[0]` не проверяется — вызывающий уже сделал switch по типу.
    pub fn decrypt(
        &mut self,
        priv_key: &BoxPriv,
        from: &EdPub,
        data: &[u8],
        auth: &GroupAuth,
    ) -> bool {
        if data.len() != SESSION_INIT_SIZE {
            return false;
        }
        let mut from_box = [0u8; BOX_PUB_SIZE];
        from_box.copy_from_slice(&data[1..=BOX_PUB_SIZE]);
        let boxed = &data[1 + BOX_PUB_SIZE..];

        let shared = get_shared(&from_box, priv_key);
        let Some(payload) = box_open(&shared, boxed, 0) else {
            return false;
        };
        if payload.len() != ED_SIG_SIZE + 80 {
            return false;
        }

        let mut sig_arr = [0u8; ED_SIG_SIZE];
        sig_arr.copy_from_slice(&payload[..ED_SIG_SIZE]);
        let sig = EdSig::from_bytes(&sig_arr);

        self.current
            .copy_from_slice(&payload[ED_SIG_SIZE..ED_SIG_SIZE + 32]);
        self.next
            .copy_from_slice(&payload[ED_SIG_SIZE + 32..ED_SIG_SIZE + 64]);

        let mut key_seq_buf = [0u8; 8];
        key_seq_buf.copy_from_slice(&payload[ED_SIG_SIZE + 64..ED_SIG_SIZE + 72]);
        self.key_seq = u64::from_be_bytes(key_seq_buf);

        let mut seq_buf = [0u8; 8];
        seq_buf.copy_from_slice(&payload[ED_SIG_SIZE + 72..ED_SIG_SIZE + 80]);
        self.seq = u64::from_be_bytes(seq_buf);

        // sigBytes = fromBox || current || next || keySeq || seq
        let mut sig_bytes = [0u8; 32 + 32 + 32 + 8 + 8];
        sig_bytes[..32].copy_from_slice(&from_box);
        sig_bytes[32..].copy_from_slice(&payload[ED_SIG_SIZE..]);

        ed_check(
            &sig_bytes,
            &sig,
            from,
            auth.preimage().map(<[u8; 32]>::as_slice),
        )
    }
}

/// `type sessionAck struct { sessionInit }`.
#[derive(Debug, Clone)]
pub struct SessionAck {
    pub init: SessionInit,
}

impl SessionAck {
    #[must_use]
    pub const fn new(init: SessionInit) -> Self {
        Self { init }
    }

    /// `func (ack *sessionAck) encrypt(from, to, auth) ([]byte, error)`.
    #[must_use]
    pub fn encrypt(&self, from: &EdPriv, to: &EdPub, auth: &GroupAuth) -> Vec<u8> {
        let mut data = self.init.encrypt(from, to, auth);
        data[0] = SESSION_TYPE_ACK;
        data
    }
}

/// `_ = Error` — на будущее (например, `Error::ENCODE` при создании
/// сессии в manager'е). Пока не нужен.
const _: () = ();
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ironwood::encrypted::crypto::{GroupAuth, ed25519_priv_to_curve25519, new_box_keys};

    #[test]
    fn init_roundtrip() {
        let alice_secret = EdPriv::from_bytes(&[0x11u8; 32]);
        let bob_secret = EdPriv::from_bytes(&[0x22u8; 32]);
        let alice_public = alice_secret.verifying_key();
        let bob_public = bob_secret.verifying_key();

        let (cur_pub, _) = new_box_keys();
        let (next_pub, _) = new_box_keys();
        let init = SessionInit::new(cur_pub, next_pub, 42);
        let auth = GroupAuth::new("");

        let wire = init.encrypt(&alice_secret, &bob_public, &auth);
        assert_eq!(wire.len(), SESSION_INIT_SIZE);
        assert_eq!(wire[0], SESSION_TYPE_INIT);

        let bob_box_priv = ed25519_priv_to_curve25519(&bob_secret);
        let mut decoded = SessionInit::new([0u8; 32], [0u8; 32], 0);
        assert!(decoded.decrypt(&bob_box_priv, &alice_public, &wire, &auth));
        assert_eq!(decoded.current, cur_pub);
        assert_eq!(decoded.next, next_pub);
        assert_eq!(decoded.key_seq, 42);
        assert_eq!(decoded.seq, init.seq);
    }

    #[test]
    fn init_wrong_password_fails() {
        let alice_secret = EdPriv::from_bytes(&[0x11u8; 32]);
        let bob_secret = EdPriv::from_bytes(&[0x22u8; 32]);
        let alice_public = alice_secret.verifying_key();
        let bob_public = bob_secret.verifying_key();

        let (cur_pub, _) = new_box_keys();
        let (next_pub, _) = new_box_keys();
        let init = SessionInit::new(cur_pub, next_pub, 0);

        let wire = init.encrypt(&alice_secret, &bob_public, &GroupAuth::new("shared"));
        let bob_box_priv = ed25519_priv_to_curve25519(&bob_secret);

        let mut decoded = SessionInit::new([0u8; 32], [0u8; 32], 0);
        assert!(!decoded.decrypt(
            &bob_box_priv,
            &alice_public,
            &wire,
            &GroupAuth::new("wrong")
        ));
        assert!(decoded.decrypt(
            &bob_box_priv,
            &alice_public,
            &wire,
            &GroupAuth::new("shared")
        ));
    }

    #[test]
    fn ack_is_init_byte() {
        let alice_sk = EdPriv::from_bytes(&[0x33u8; 32]);
        let bob_pk = EdPriv::from_bytes(&[0x44u8; 32]).verifying_key();
        let (cur, _) = new_box_keys();
        let (nxt, _) = new_box_keys();
        let ack = SessionAck::new(SessionInit::new(cur, nxt, 7));
        let wire = ack.encrypt(&alice_sk, &bob_pk, &GroupAuth::new(""));
        assert_eq!(wire.len(), SESSION_ACK_SIZE);
        assert_eq!(wire[0], SESSION_TYPE_ACK);
    }
}
