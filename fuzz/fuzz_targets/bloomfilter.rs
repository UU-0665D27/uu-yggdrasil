#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{Bloom, WireEncodable};

fuzz_target!(|data: &[u8]| {
    // Roundtrip decode → encode → decode.
    if let Ok(b) = Bloom::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&b));
        b.encode(&mut out).expect("encode");
        assert_eq!(out.len(), WireEncodable::size(&b));
        let b2 = Bloom::decode(&out).expect("re-decode");
        assert_eq!(b, b2);

        // Все ключи, что «точно в фильтре», не должны давать ложный
        // отрицательный ответ. Тестируем на произвольных байтах: test
        // детерминирован, никаких паник не должно быть.
        let _ = b.test(&[0u8; 32]);
        let _ = b.test(data);
    }

    // Программная сборка: new + add_bytes + merge + encode/decode.
    let mut b = Bloom::new();
    b.add_bytes(data);
    let mut out = Vec::new();
    b.encode(&mut out).expect("encode built");
    let b2 = Bloom::decode(&out).expect("decode built");
    assert_eq!(b, b2);

    // add_* не должен паниковать ни на каком входе.
    let mut c = Bloom::new();
    c.add_bytes(&[]);
    c.add_bytes(&[0xFFu8; 100]);
    c.merge(&b);
});
