#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    PrivateKey, PublicKey, Traffic, WireEncodable, packet_queue::PacketQueue,
};

/// Детерминированный, но валидный публичный ключ из одного байта.
fn key_from(b: u8) -> PublicKey {
    let mut seed = [0u8; 32];
    seed[0] = b;
    seed[31] = b.wrapping_mul(0x9E); // разные b — точно разные ключи
    PrivateKey::from_bytes(&seed).verifying_key()
}

fn make_traffic(src: u8, dst: u8, payload: &[u8]) -> Traffic {
    Traffic {
        path: Vec::new(),
        from: Vec::new(),
        source: key_from(src),
        dest: key_from(dst),
        watermark: 0,
        payload: payload.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut q = PacketQueue::new();
    let mut expected_size: u64 = 0;

    for &b in data {
        let op = b & 1;
        let src = (b >> 1) & 0x07;
        let dst = (b >> 4) & 0x07;
        let payload_len = if b & 0x80 != 0 { 15 } else { 0 };

        if op == 0 {
            let payload = vec![0xAAu8; payload_len];
            let tr = make_traffic(src, dst, &payload);
            let sz = WireEncodable::size(&tr) as u64;
            q.push(Box::new(tr));
            expected_size += sz;
        } else {
            if let Some(p) = q.pop() {
                expected_size -= p.size() as u64;
            }
        }

        assert_eq!(q.size(), expected_size, "size invariant violated");
    }

    while q.drop_oldest() {}
    assert_eq!(q.size(), 0, "queue not empty after drain");
});
