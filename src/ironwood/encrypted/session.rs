//! Handshake `encrypted`-слоя: `sessionInit`/`sessionAck`.
//!
//! Формат `sessionInit` (193 байта, `sessionAckSize == sessionInitSize`):
//! `[type:1][fromBoxPub:32][boxed:160]`,
//! где `boxed = XSalsa20Poly1305(key, nonce=0, payload)`, `payload = sig(64) || current(32) || next(32) || keySeq(BE8) || seq(BE8)`.
//!
//! `sig` — Ed25519-подпись от `fromBoxPub || current || next || keySeq || seq`,
//! с `groupAuth.preimage()` в качестве префикса.

use crypto_box::SalsaBox;

use crate::ironwood::{
    encrypted::crypto::{
        BOX_OVERHEAD, BOX_PUB_SIZE, BoxPriv, BoxPub, ED_SIG_SIZE, EdPriv, EdPub, EdSig, GroupAuth,
        box_open, box_seal, ed_check, ed_sign, ed25519_priv_to_curve25519,
        ed25519_pub_to_curve25519, get_shared, new_box_keys,
    },
    network::wire::{wire_append_uint, wire_chop_uint},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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

// ════════════════════════════════════════════════════════════════════
// SessionBuffer
// ════════════════════════════════════════════════════════════════════

/// `sessionBuffer` — отложенный трафик и priv-ключи для не-установленной сессии.
pub struct SessionBuffer {
    /// Трафик, ожидающий установления сессии.
    pub data: Option<Vec<u8>>,
    /// Init, который мы отправили.
    pub init: SessionInit,
    /// Приватный ключ, парный к `init.current`.
    pub current_priv: BoxPriv,
    /// Приватный ключ, парный к `init.next`.
    pub next_priv: BoxPriv,
    /// Момент последней активности (для expiry).
    pub last_seen: std::time::Instant,
}

impl SessionBuffer {
    #[must_use]
    pub fn new(now: std::time::Instant) -> Self {
        let (current_pub, current_priv) = new_box_keys();
        let (next_pub, next_priv) = new_box_keys();
        Self {
            data: None,
            init: SessionInit::new(current_pub, next_pub, 0),
            current_priv,
            next_priv,
            last_seen: now,
        }
    }

    #[must_use]
    pub fn is_expired(&self, now: std::time::Instant) -> bool {
        now.duration_since(self.last_seen) >= SESSION_TIMEOUT
    }
}

// ════════════════════════════════════════════════════════════════════
// RecvResult
// ════════════════════════════════════════════════════════════════════

/// Результат `SessionInfo::do_recv`.
pub enum RecvResult {
    /// Расшифровано — приложить к приёмной очереди.
    Delivered(Vec<u8>),
    /// Мы вне синхронизации — надо отослать `sessionInit`.
    NeedsInit,
    /// Пакет дублирующий, битый или непонятный — молча дроп.
    Drop,
}

// ════════════════════════════════════════════════════════════════════
// SessionInfo
// ════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy)]
enum RotateMode {
    CurrentRecv,
    NextSend,
    NextRecv,
}

/// `sessionInfo` — полное состояние ratchet'а.
pub struct SessionInfo {
    // Remote.
    pub ed: EdPub,
    pub seq: u64,
    pub remote_key_seq: u64,
    pub current: BoxPub,
    pub next: BoxPub,

    // Local.
    pub local_key_seq: u64,
    pub recv_pub: BoxPub,
    pub recv_priv: BoxPriv,
    pub recv_shared: SalsaBox,
    pub recv_nonce: u64,
    pub send_pub: BoxPub,
    pub send_priv: BoxPriv,
    pub send_shared: SalsaBox,
    pub send_nonce: u64,
    pub next_priv: BoxPriv,
    pub next_pub: BoxPub,

    // Ratchet-forward.
    pub next_send_shared: SalsaBox,
    pub next_send_nonce: u64,
    pub next_recv_shared: SalsaBox,
    pub next_recv_nonce: u64,

    // Misc.
    pub since: std::time::Instant,
    pub rotated: Option<std::time::Instant>,
    pub last_seen: std::time::Instant,
    pub rx: u64,
    pub tx: u64,
}

impl SessionInfo {
    #[must_use]
    pub fn new(
        ed: EdPub,
        current: BoxPub,
        next: BoxPub,
        seq: u64,
        now: std::time::Instant,
    ) -> Self {
        let (recv_pub, recv_priv) = new_box_keys();
        let (send_pub, send_priv) = new_box_keys();
        let (next_pub, next_priv) = new_box_keys();
        let recv_shared = get_shared(&current, &recv_priv);
        let send_shared = get_shared(&current, &send_priv);
        let next_send_shared = get_shared(&next, &send_priv);
        let next_recv_shared = get_shared(&next, &recv_priv);
        Self {
            ed,
            seq: seq.wrapping_sub(1),
            remote_key_seq: 0,
            current,
            next,
            local_key_seq: 0,
            recv_pub,
            recv_priv,
            recv_shared,
            recv_nonce: 0,
            send_pub,
            send_priv,
            send_shared,
            send_nonce: 0,
            next_priv,
            next_pub,
            next_send_shared,
            next_send_nonce: 0,
            next_recv_shared,
            next_recv_nonce: 0,
            since: now,
            rotated: None,
            last_seen: now,
            rx: 0,
            tx: 0,
        }
    }

    fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        self.recv_shared = get_shared(&self.current, &self.recv_priv);
        self.send_shared = get_shared(&self.current, &self.send_priv);
        self.next_send_shared = get_shared(&self.next, &self.send_priv);
        self.next_recv_shared = get_shared(&self.next, &self.recv_priv);
        self.next_send_nonce = 0;
        self.next_recv_nonce = 0;
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }

    /// `_handleUpdate`: применить init/ack, прокрутить наши ключи вперёд.
    pub fn handle_update(&mut self, init: &SessionInit, now: std::time::Instant) {
        self.current = init.current;
        self.next = init.next;
        self.seq = init.seq;
        self.remote_key_seq = init.key_seq;

        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        let (np, npr) = new_box_keys();
        self.next_pub = np;
        self.next_priv = npr;
        self.local_key_seq = self.local_key_seq.wrapping_add(1);

        let sn = self.send_nonce;
        self.fix_shared(0, sn);
        self.last_seen = now;
    }

    fn maybe_rotate(&mut self, inner_key: BoxPub, nonce: u64, now: std::time::Instant) {
        let should_rotate = self
            .rotated
            .is_none_or(|t| now.duration_since(t) > std::time::Duration::from_secs(60));
        if !should_rotate {
            return;
        }
        self.current = self.next;
        self.next = inner_key;
        self.remote_key_seq = self.remote_key_seq.wrapping_add(1);
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        let (np, npr) = new_box_keys();
        self.next_pub = np;
        self.next_priv = npr;
        self.local_key_seq = self.local_key_seq.wrapping_add(1);
        self.fix_shared(nonce, 0);
        self.rotated = Some(now);
    }

    /// `doSend`: зашифровать `msg`, вернуть готовый wire-пакет.
    pub fn do_send(&mut self, msg: &[u8], now: std::time::Instant) -> Vec<u8> {
        self.send_nonce = self.send_nonce.wrapping_add(1);
        if self.send_nonce == 0 {
            self.recv_pub = self.send_pub;
            self.recv_priv = self.send_priv;
            self.send_pub = self.next_pub;
            self.send_priv = self.next_priv;
            let (np, npr) = new_box_keys();
            self.next_pub = np;
            self.next_priv = npr;
            self.local_key_seq = self.local_key_seq.wrapping_add(1);
            self.fix_shared(0, 0);
        }

        let mut out = vec![SESSION_TYPE_TRAFFIC];
        wire_append_uint(&mut out, self.local_key_seq);
        wire_append_uint(&mut out, self.remote_key_seq);
        wire_append_uint(&mut out, self.send_nonce);

        let mut plaintext = Vec::with_capacity(BOX_PUB_SIZE + msg.len());
        plaintext.extend_from_slice(&self.next_pub);
        plaintext.extend_from_slice(msg);

        let boxed = box_seal(&self.send_shared, &plaintext, self.send_nonce);
        out.extend_from_slice(&boxed);
        self.tx += msg.len() as u64;
        self.last_seen = now;
        out
    }

    /// `doRecv`: расшифровать входящий wire-пакет.
    pub fn do_recv(&mut self, msg: &[u8], now: std::time::Instant) -> RecvResult {
        if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN || msg[0] != SESSION_TYPE_TRAFFIC {
            return RecvResult::Drop;
        }
        let mut slice = &msg[1..];
        let Some(remote_key_seq) = wire_chop_uint(&mut slice) else {
            return RecvResult::Drop;
        };
        let Some(local_key_seq) = wire_chop_uint(&mut slice) else {
            return RecvResult::Drop;
        };
        let Some(nonce) = wire_chop_uint(&mut slice) else {
            return RecvResult::Drop;
        };
        let boxed = slice;

        let from_current = remote_key_seq == self.remote_key_seq;
        let from_next = remote_key_seq == self.remote_key_seq.wrapping_add(1);
        let to_recv = local_key_seq.wrapping_add(1) == self.local_key_seq;
        let to_send = local_key_seq == self.local_key_seq;

        let mode = if from_current && to_recv {
            if self.recv_nonce >= nonce {
                return RecvResult::Drop;
            }
            RotateMode::CurrentRecv
        } else if from_next && to_send {
            if self.next_send_nonce >= nonce {
                return RecvResult::Drop;
            }
            RotateMode::NextSend
        } else if from_next && to_recv {
            if self.next_recv_nonce >= nonce {
                return RecvResult::Drop;
            }
            RotateMode::NextRecv
        } else {
            return RecvResult::NeedsInit;
        };

        let shared = match mode {
            RotateMode::CurrentRecv => &self.recv_shared,
            RotateMode::NextSend => &self.next_send_shared,
            RotateMode::NextRecv => &self.next_recv_shared,
        };

        let Some(plaintext) = box_open(shared, boxed, nonce) else {
            return RecvResult::NeedsInit;
        };
        if plaintext.len() < BOX_PUB_SIZE {
            return RecvResult::Drop;
        }
        let mut inner_key = [0u8; BOX_PUB_SIZE];
        inner_key.copy_from_slice(&plaintext[..BOX_PUB_SIZE]);
        let payload = plaintext[BOX_PUB_SIZE..].to_vec();

        match mode {
            RotateMode::CurrentRecv => {
                self.recv_nonce = nonce;
            }
            RotateMode::NextSend => {
                self.next_send_nonce = nonce;
                self.maybe_rotate(inner_key, nonce, now);
            }
            RotateMode::NextRecv => {
                self.next_recv_nonce = nonce;
                self.maybe_rotate(inner_key, nonce, now);
            }
        }
        self.rx += payload.len() as u64;
        self.last_seen = now;
        RecvResult::Delivered(payload)
    }

    /// `_sendInit`.
    #[must_use]
    pub fn build_init(&self, secret_ed: &EdPriv, group_auth: &GroupAuth) -> Vec<u8> {
        let init = SessionInit::new(self.send_pub, self.next_pub, self.local_key_seq);
        init.encrypt(secret_ed, &self.ed, group_auth)
    }

    /// `_sendAck`.
    #[must_use]
    pub fn build_ack(&self, secret_ed: &EdPriv, group_auth: &GroupAuth) -> Vec<u8> {
        let init = SessionInit::new(self.send_pub, self.next_pub, self.local_key_seq);
        SessionAck::new(init).encrypt(secret_ed, &self.ed, group_auth)
    }

    /// `handleInit`: обновить состояние + вернуть байты ack'а.
    pub fn handle_init(
        &mut self,
        init: &SessionInit,
        secret_ed: &EdPriv,
        group_auth: &GroupAuth,
        now: std::time::Instant,
    ) -> Option<Vec<u8>> {
        if init.seq <= self.seq {
            return None;
        }
        self.handle_update(init, now);
        Some(self.build_ack(secret_ed, group_auth))
    }

    /// `handleAck`: обновить состояние (без ack'а назад).
    pub fn handle_ack(&mut self, ack: &SessionAck, now: std::time::Instant) {
        if ack.init.seq <= self.seq {
            return;
        }
        self.handle_update(&ack.init, now);
    }

    #[must_use]
    pub fn is_expired(&self, now: std::time::Instant) -> bool {
        now.duration_since(self.last_seen) >= SESSION_TIMEOUT
    }
}

// ════════════════════════════════════════════════════════════════════
// SessionManager
// ════════════════════════════════════════════════════════════════════

/// События, которые `SessionManager` возвращает наружу.
///
/// `Send` — отправить `data` на `dest` через `network::PacketConn::send_to`.
/// `Deliver` — входящий расшифрованный payload, доставить в `ReadFrom`.
pub enum SessionEvent {
    /// Wire-фрейм для отправки через `network::PacketConn::send_to`.
    Send { dest: EdPub, data: Vec<u8> },
    /// Расшифрованный payload — доставить в `ReadFrom`-очередь.
    Deliver { from: EdPub, payload: Vec<u8> },
}

/// `sessionManager`: держит `sessions` и `buffers`, управляет handshake'ом.
///
/// Не знает про `network::PacketConn` — возвращает `SessionEvent::Send`,
/// а caller сам делает `send_to`. В этом отличие от Go-версии, где
/// `mgr.pc.PacketConn.WriteTo` вызывается напрямую.
pub struct SessionManager {
    secret_ed: EdPriv,
    secret_box: BoxPriv,
    group_auth: GroupAuth,
    sessions: HashMap<EdPub, SessionInfo>,
    buffers: HashMap<EdPub, SessionBuffer>,
}

impl SessionManager {
    #[must_use]
    pub fn new(secret_ed: EdPriv, group_auth: GroupAuth) -> Self {
        let secret_box = ed25519_priv_to_curve25519(&secret_ed);
        Self {
            secret_ed,
            secret_box,
            group_auth,
            sessions: HashMap::new(),
            buffers: HashMap::new(),
        }
    }

    /// `handleData(from, data)`. Возвращает события для диспетчеризации.
    #[must_use]
    pub fn handle_data(&mut self, from: EdPub, data: &[u8], now: Instant) -> Vec<SessionEvent> {
        let mut out = Vec::new();
        if data.is_empty() {
            return out;
        }
        match data[0] {
            SESSION_TYPE_INIT => {
                let mut init = SessionInit::new([0u8; 32], [0u8; 32], 0);
                if init.decrypt(&self.secret_box, &from, data, &self.group_auth) {
                    self.handle_init(from, &init, now, &mut out);
                }
            }
            SESSION_TYPE_ACK => {
                let mut ack_init = SessionInit::new([0u8; 32], [0u8; 32], 0);
                if ack_init.decrypt(&self.secret_box, &from, data, &self.group_auth) {
                    let ack = SessionAck::new(ack_init);
                    self.handle_ack(from, &ack, now, &mut out);
                }
            }
            SESSION_TYPE_TRAFFIC => {
                self.handle_traffic(from, data, now, &mut out);
            }
            // `SESSION_TYPE_DUMMY` и всё неизвестное — молча игнорируем.
            _ => {}
        }
        out
    }

    /// `writeTo(toKey, msg)` — отправить `msg` на `toKey`.
    /// Если сессии нет — создаёт буфер, отправляет `sessionInit`,
    /// а `msg` откладывает до установки сессии.
    #[must_use]
    pub fn write_to(&mut self, to: EdPub, msg: Vec<u8>, now: Instant) -> Vec<SessionEvent> {
        let mut out = Vec::new();
        if let Some(session) = self.sessions.get_mut(&to) {
            let wire = session.do_send(&msg, now);
            out.push(SessionEvent::Send {
                dest: to,
                data: wire,
            });
        } else {
            self.buffer_and_init(to, msg, now, &mut out);
        }
        out
    }

    /// `_handleInit(pub, init)`.
    fn handle_init(
        &mut self,
        from: EdPub,
        init: &SessionInit,
        now: Instant,
        out: &mut Vec<SessionEvent>,
    ) {
        let buffered_data = self.session_for_init(from, init, now);
        if let Some(session) = self.sessions.get_mut(&from) {
            if let Some(ack_wire) =
                session.handle_init(init, &self.secret_ed, &self.group_auth, now)
            {
                out.push(SessionEvent::Send {
                    dest: from,
                    data: ack_wire,
                });
            }
            if let Some(msg) = buffered_data {
                let wire = session.do_send(&msg, now);
                out.push(SessionEvent::Send {
                    dest: from,
                    data: wire,
                });
            }
        }
    }

    /// `_handleAck(pub, ack)`.
    fn handle_ack(
        &mut self,
        from: EdPub,
        ack: &SessionAck,
        now: Instant,
        out: &mut Vec<SessionEvent>,
    ) {
        let was_old = self.sessions.contains_key(&from);
        let buffered_data = self.session_for_init(from, &ack.init, now);
        if let Some(session) = self.sessions.get_mut(&from) {
            if was_old {
                session.handle_ack(ack, now);
            } else if let Some(ack_wire) =
                session.handle_init(&ack.init, &self.secret_ed, &self.group_auth, now)
            {
                out.push(SessionEvent::Send {
                    dest: from,
                    data: ack_wire,
                });
            }
            if let Some(msg) = buffered_data {
                let wire = session.do_send(&msg, now);
                out.push(SessionEvent::Send {
                    dest: from,
                    data: wire,
                });
            }
        }
    }

    /// `_handleTraffic(pub, msg)`.
    fn handle_traffic(
        &mut self,
        from: EdPub,
        data: &[u8],
        now: Instant,
        out: &mut Vec<SessionEvent>,
    ) {
        if let Some(session) = self.sessions.get_mut(&from) {
            match session.do_recv(data, now) {
                RecvResult::Delivered(payload) => {
                    out.push(SessionEvent::Deliver { from, payload });
                }
                RecvResult::NeedsInit => {
                    let init_wire = session.build_init(&self.secret_ed, &self.group_auth);
                    out.push(SessionEvent::Send {
                        dest: from,
                        data: init_wire,
                    });
                }
                RecvResult::Drop => {}
            }
        } else {
            // Сессии нет — вероятно, спуф/реплей. Не сохраняем сессию
            // и не буферизуем; шлём «слепой» init, чтобы пир прислал ack
            // и инициировал установку. Ключи забываем.
            let (cur_pub, _cur_priv) = new_box_keys();
            let (nxt_pub, _nxt_priv) = new_box_keys();
            let init = SessionInit::new(cur_pub, nxt_pub, 0);
            let wire = init.encrypt(&self.secret_ed, &from, &self.group_auth);
            out.push(SessionEvent::Send {
                dest: from,
                data: wire,
            });
        }
    }

    /// `_sessionForInit(pub, init)`: создать сессию (или ничего, если уже
    /// есть), трансплантировать ключи из буфера, вернуть отложенные данные.
    fn session_for_init(
        &mut self,
        from: EdPub,
        init: &SessionInit,
        now: Instant,
    ) -> Option<Vec<u8>> {
        if self.sessions.contains_key(&from) {
            return None;
        }

        let mut session = SessionInfo::new(from, init.current, init.next, init.seq, now);

        let buffered_data = if let Some(mut buf) = self.buffers.remove(&from) {
            session.send_pub = buf.init.current;
            session.send_priv = buf.current_priv;
            session.next_pub = buf.init.next;
            session.next_priv = buf.next_priv;
            session.fix_shared(0, 0);
            buf.data.take()
        } else {
            None
        };

        self.sessions.insert(from, session);
        buffered_data
    }

    /// `_bufferAndInit(toKey, msg)`.
    fn buffer_and_init(
        &mut self,
        to: EdPub,
        msg: Vec<u8>,
        now: Instant,
        out: &mut Vec<SessionEvent>,
    ) {
        let buf = self
            .buffers
            .entry(to)
            .or_insert_with(|| SessionBuffer::new(now));
        buf.data = Some(msg);
        buf.last_seen = now;
        let init_wire = buf.init.encrypt(&self.secret_ed, &to, &self.group_auth);
        out.push(SessionEvent::Send {
            dest: to,
            data: init_wire,
        });
    }

    /// Пройтись по сессиям и буферам, удалить просроченные.
    pub fn do_maintenance(&mut self, now: Instant) {
        self.buffers.retain(|_, buf| !buf.is_expired(now));
        self.sessions.retain(|_, session| !session.is_expired(now));
    }

    /// Количество активных сессий (для отладки).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Количество буферов начатых handshake'ей (для отладки).
    #[must_use]
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }
}

/// `_ = Error` — на будущее (например, `Error::ENCODE` при создании
/// сессии в manager'е). Пока не нужен.
const _: () = ();

#[cfg(test)]
mod tests {
    use crate::ironwood::encrypted::{
        crypto::{EdPriv, GroupAuth, ed25519_priv_to_curve25519, new_box_keys},
        session::{
            RecvResult, SESSION_ACK_SIZE, SESSION_INIT_SIZE, SESSION_TIMEOUT, SESSION_TYPE_ACK,
            SESSION_TYPE_INIT, SESSION_TYPE_TRAFFIC, SessionAck, SessionBuffer, SessionEvent,
            SessionInfo, SessionInit, SessionManager,
        },
    };

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
    #[test]
    fn session_traffic_normal_case() {
        let (common_pub, common_priv) = new_box_keys();
        let ed_pub = EdPriv::from_bytes(&[0x11u8; 32]).verifying_key();
        let now = std::time::Instant::now();

        // Bob: local=1, remote=0 (он на своей текущей, думает что alice на 0)
        let mut bob = SessionInfo::new(ed_pub, common_pub, common_pub, 0, now);
        bob.send_priv = common_priv;
        bob.send_pub = common_pub;
        bob.local_key_seq = 1;
        bob.remote_key_seq = 0;
        bob.fix_shared(0, 0);

        // Alice: local=1, remote=1 (думает что bob на 1 - т.е. отстаёт на 1)
        let mut alice = SessionInfo::new(ed_pub, common_pub, common_pub, 0, now);
        alice.recv_priv = common_priv;
        alice.recv_pub = common_pub;
        alice.local_key_seq = 1;
        alice.remote_key_seq = 1;
        alice.fix_shared(0, 0);

        // bob.send_shared == alice.recv_shared, потому что оба используют
        // DH(common_pub, common_priv).
        let wire = bob.do_send(b"hello", now);
        match alice.do_recv(&wire, now) {
            RecvResult::Delivered(data) => assert_eq!(data, b"hello"),
            _ => panic!("expected delivery"),
        }
    }

    #[test]
    fn session_buffer_expiry() {
        let now = std::time::Instant::now();
        let buf = SessionBuffer::new(now);
        assert!(!buf.is_expired(now));
        assert!(buf.is_expired(now + SESSION_TIMEOUT));
        assert!(buf.is_expired(now + SESSION_TIMEOUT + std::time::Duration::from_secs(1)));
    }
    #[test]
    fn manager_two_party_handshake() {
        let alice_ed = EdPriv::from_bytes(&[0x51u8; 32]);
        let bob_ed = EdPriv::from_bytes(&[0x52u8; 32]);
        let alice_pub = alice_ed.verifying_key();
        let bob_pub = bob_ed.verifying_key();
        let now = std::time::Instant::now();
        let auth = GroupAuth::new("");

        let mut alice = SessionManager::new(alice_ed, auth.clone());
        let mut bob = SessionManager::new(bob_ed, auth);

        // Alice шлёт Bob'у — сессии нет, должен пойти init.
        let events = alice.write_to(bob_pub, b"hello".to_vec(), now);
        assert_eq!(events.len(), 1);
        let SessionEvent::Send { dest, data } = &events[0] else {
            panic!("expected Send");
        };
        assert_eq!(*dest, bob_pub);
        let init_wire = data.clone();

        // Bob получает init → должен создать сессию и отправить ack.
        let events = bob.handle_data(alice_pub, &init_wire, now);
        assert_eq!(events.len(), 1);
        let SessionEvent::Send { data: ack_wire, .. } = &events[0] else {
            panic!("expected ack Send");
        };
        let ack_wire = ack_wire.clone();
        assert_eq!(bob.session_count(), 1);

        // Alice получает ack → создаёт сессию + отправляет отложенный hello.
        let events = alice.handle_data(bob_pub, &ack_wire, now);
        assert_eq!(alice.session_count(), 1);
        // Alice отвечает ack'ом на ack (self-heal, как в Go) и затем шлёт
        // отложенный traffic. Нас интересует именно traffic.
        let traffic_send = events
            .iter()
            .find(
                |e| matches!(e, SessionEvent::Send { data, .. } if data[0] == SESSION_TYPE_TRAFFIC),
            )
            .expect("alice should send traffic");
        let SessionEvent::Send {
            data: traffic_wire, ..
        } = traffic_send
        else {
            unreachable!()
        };
        let traffic_wire = traffic_wire.clone();

        // Bob получает traffic → должен доставить "hello".
        let events = bob.handle_data(alice_pub, &traffic_wire, now);
        let delivered = events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Deliver { from, payload } => Some((*from, payload.clone())),
                SessionEvent::Send { .. } => None,
            })
            .expect("bob should deliver payload");
        assert_eq!(delivered.0, alice_pub);
        assert_eq!(delivered.1, b"hello");
    }
}
