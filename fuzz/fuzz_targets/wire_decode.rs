#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    WireEncodable,
    traffic::Traffic,
    wire::{WirePacketType, wire_chop_uint, wire_decode_path},
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let Ok(_ptype) = WirePacketType::try_from_byte(data[0]) else {
        return;
    };
    let body = &data[1..];

    let mut rest = body;
    let _ = wire_chop_uint(&mut rest);
    let _ = wire_decode_path(body);

    if let Ok(tr) = Traffic::decode(body) {
        let mut out = Vec::with_capacity(WireEncodable::size(&tr) + 1);
        out.push(WirePacketType::Traffic as u8);
        tr.encode(&mut out).expect("encode");
        assert_eq!(out.len(), WireEncodable::size(&tr) + 1);

        let tr2 = Traffic::decode(&out[1..]).expect("re-decode after encode");
        let mut out2 = Vec::with_capacity(WireEncodable::size(&tr2) + 1);
        out2.push(WirePacketType::Traffic as u8);
        tr2.encode(&mut out2).expect("re-encode");
        assert_eq!(out, out2, "roundtrip not stable");
    }
});
