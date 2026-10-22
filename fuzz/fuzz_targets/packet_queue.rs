#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    PublicKey, Traffic, WireEncodable,
    packet_queue::{PacketQueue, PqPacket},
};

fn make_traffic(src: u8, dst: u8, payload: &[u8]) -> Traffic {
    let mut sk = [0u8; 32];
    sk[0] = src;
    let mut dk = [0u8; 32];
    dk[0] = dst;
    Traffic {
        path: Vec::new(),
        from: Vec::new(),
        source: PublicKey::from_bytes(&sk).expect("valid key"),
        dest: PublicKey::from_bytes(&dk).expect("valid key"),
        watermark: 0,
        payload: payload.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    // Каждый байт входа — инструкция:
    //   bit 0: push или pop
    //   bits 1..3: src selector (0..7)
    //   bits 4..6: dst selector (0..7)
    //   bit 7: длина payload (0 или 15)
    //
    // После каждой операции — инвариант `size == sum(traffic.size())`.
    // Любое расхождение = баг в очереди.
    let mut q = PacketQueue::new();
    let mut expected_size: u64 = 0;

    for &b in data {
        let op = b & 1;
        let src = (b >> 1) & 0x07;
        let dst = (b >> 4) & 0x07;
        let payload_len = if b & 0x80 != 0 { 15 } else { 0 };

        if op == 0 {
            // push
            let payload = vec![0xAAu8; payload_len];
            let tr = make_traffic(src, dst, &payload);
            let sz = WireEncodable::size(&tr) as u64;
            q.push(Box::new(tr));
            expected_size += sz;
        } else {
            // pop, если есть
            if let Some(p) = q.pop() {
                expected_size -= p.size() as u64;
            }
        }

        assert_eq!(q.size(), expected_size, "size invariant violated");
    }

    // Финальная уборка через drop_oldest — инвариант тоже должен сохраняться.
    while q.drop_oldest() {}
    assert_eq!(q.size(), 0, "queue not empty after drain");
});
