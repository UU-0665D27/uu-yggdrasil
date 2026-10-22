#![no_main]

use libfuzzer_sys::fuzz_target;

use std::io::Cursor;
use uu_yggdrasil::ironwood::{
    PacketConnBase,
    errors::Error,
    network::{Config, Ironwood, PrivateKey},
    types::packetconn::PacketConn as PacketConnTrait,
};

const MAX_FRAME: u64 = 1_048_576;

fuzz_target!(|data: &[u8]| {
    // Формат: [our_seed8 | peer_seed8 | wire_bytes...]
    if data.len() < 16 {
        return;
    }

    let mut our_seed = [0u8; 32];
    our_seed[..8].copy_from_slice(&data[..8]);
    let our_key = PrivateKey::from_bytes(&our_seed);

    let mut peer_seed = [0u8; 32];
    peer_seed[..8].copy_from_slice(&data[8..16]);
    let peer_key = PrivateKey::from_bytes(&peer_seed).verifying_key();

    // Наш узел.
    let node = match Ironwood::new(
        &our_key,
        Config::default().with_peer_max_message_size(MAX_FRAME),
    ) {
        Ok(n) => n,
        Err(_) => return,
    };

    // Reader-цикл через sync handle_conn_sync.
    let mut conn = Cursor::new(data[16..].to_vec());
    let _ = node.handle_conn_sync(&peer_key, &mut conn, 0);

    // Упражняем Blooms + maintenance.
    node.do_maintenance();

    // После выхода сессии узел должен быть консистентен.
    assert!(!node.is_closed());
    let _ = node.mtu();
    let _ = PacketConnTrait::private_key(node.as_ref());
    let _ = node.local_addr();
    let _ = node.close();
    assert!(node.is_closed());
    assert_eq!(node.close(), Err(Error::CLOSED));
});
