#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    WireEncodable,
    router::types::{RouterAnnounce, RouterSigReq, RouterSigRes},
};

/// Каждый decode с последующим re-encode должен давать стабильный roundtrip.
/// Плюс `check()` не должен паниковать ни на каком входе.
fuzz_target!(|data: &[u8]| {
    if let Ok(req) = RouterSigReq::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&req));
        req.encode(&mut out).expect("encode req");
        assert_eq!(out.len(), WireEncodable::size(&req));
        let req2 = RouterSigReq::decode(&out).expect("re-decode req");
        assert_eq!(req, req2);
    }

    if let Ok(res) = RouterSigRes::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&res));
        res.encode(&mut out).expect("encode res");
        assert_eq!(out.len(), WireEncodable::size(&res));
        let res2 = RouterSigRes::decode(&out).expect("re-decode res");
        assert_eq!(res, res2);
    }

    if let Ok(ann) = RouterAnnounce::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&ann));
        ann.encode(&mut out).expect("encode ann");
        assert_eq!(out.len(), WireEncodable::size(&ann));
        let ann2 = RouterAnnounce::decode(&out).expect("re-decode ann");
        assert_eq!(ann, ann2);
        // check() не должен паниковать
        let _ = ann.check();
    }
});
