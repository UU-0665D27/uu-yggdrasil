#![no_main]

use libfuzzer_sys::fuzz_target;

use std::io::Cursor;

use tokio::sync::mpsc;

use uu_yggdrasil::ironwood::network::{
    PrivateKey, Traffic,
    peer::{InFrame, OutFrame, PacketDispatcher, Peer, PeerHandle, session_loop},
};

/// Dispatcher, который на всё отвечает keepalive'ом; на `Traffic` — эхом.
/// Покрывает путь `encode_frame` для `KeepAlive` и `Traffic`.
struct EchoDispatcher;

impl PacketDispatcher for EchoDispatcher {
    fn dispatch(
        &mut self,
        peer: &dyn PeerHandle,
        frame: InFrame,
    ) -> Result<(), uu_yggdrasil::ironwood::errors::Error> {
        peer.send(OutFrame::KeepAlive);
        if let InFrame::Traffic(tr) = frame {
            peer.send(OutFrame::Traffic(Box::new(Traffic {
                path: Vec::new(),
                from: Vec::new(),
                source: tr.dest,
                dest: tr.source,
                watermark: 0,
                payload: Vec::new(),
            })));
        }
        Ok(())
    }
}

const MAX_FRAME: u64 = 1_048_576;

fuzz_target!(|data: &[u8]| {
    // Формат входа: [seed8 | wire_bytes...]. seed8 — детерминированный
    // ключ пира; остальное — сырые wire-байты от него.
    if data.len() < 8 {
        return;
    }

    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&data[..8]);
    let peer_key = PrivateKey::from_bytes(&seed).verifying_key();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let peer = Peer::new(peer_key, 1, 0, 0, tx);

    let mut dispatcher = EchoDispatcher;
    let mut conn = Cursor::new(data[8..].to_vec());

    let _ = session_loop(&peer, &mut conn, &mut dispatcher, MAX_FRAME);

    // Проверка: всё, что dispatcher положил в канал, кодируется без паник.
    while let Ok(frame) = rx.try_recv() {
        let _ = uu_yggdrasil::ironwood::network::peer::encode_frame(&frame);
    }
});
