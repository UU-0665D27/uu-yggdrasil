#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    Bloom, PathBroken, PathLookup, PathNotify, RouterAnnounce, RouterSigReq, RouterSigRes, Traffic,
    WireEncodable, WirePacketType,
};

// Аналог `FuzzPeerHandlePacket`: диспетчеризация по байту типа — как
// в `Peer::handle_packet`. Каждый decode не должен паниковать.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let Ok(ptype) = WirePacketType::try_from_byte(data[0]) else {
        return;
    };
    let body = &data[1..];

    match ptype {
        WirePacketType::Dummy | WirePacketType::KeepAlive => {}
        WirePacketType::ProtoSigReq => {
            let _ = RouterSigReq::decode(body);
        }
        WirePacketType::ProtoSigRes => {
            let _ = RouterSigRes::decode(body);
        }
        WirePacketType::ProtoAnnounce => {
            if let Ok(ann) = RouterAnnounce::decode(body) {
                let _ = ann.check();
            }
        }
        WirePacketType::ProtoBloomFilter => {
            let _ = Bloom::decode(body);
        }
        WirePacketType::ProtoPathLookup => {
            let _ = PathLookup::decode(body);
        }
        WirePacketType::ProtoPathNotify => {
            if let Ok(n) = PathNotify::decode(body) {
                let _ = n.check();
            }
        }
        WirePacketType::ProtoPathBroken => {
            let _ = PathBroken::decode(body);
        }
        WirePacketType::Traffic => {
            if let Ok(tr) = Traffic::decode(body) {
                let mut out = Vec::new();
                tr.encode(&mut out).expect("re-encode");
                let tr2 = Traffic::decode(&out).expect("re-decode");
                // Stability-инвариант: encode(decode(x)) == x.
                let mut out2 = Vec::new();
                tr2.encode(&mut out2).expect("re-encode");
                assert_eq!(out, out2);
            }
        }
    }
});
