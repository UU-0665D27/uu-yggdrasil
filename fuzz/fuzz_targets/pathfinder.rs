#![no_main]

use libfuzzer_sys::fuzz_target;

use uu_yggdrasil::ironwood::network::{
    PathBroken, PathLookup, PathNotify, PathNotifyInfo, WireEncodable,
};

fuzz_target!(|data: &[u8]| {
    // PathLookup roundtrip.
    if let Ok(v) = PathLookup::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&v));
        v.encode(&mut out).expect("encode");
        assert_eq!(out.len(), WireEncodable::size(&v));
        let v2 = PathLookup::decode(&out).expect("re-decode");
        assert_eq!(v, v2);
    }

    // PathNotifyInfo roundtrip.
    if let Ok(v) = PathNotifyInfo::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&v));
        v.encode(&mut out).expect("encode");
        let v2 = PathNotifyInfo::decode(&out).expect("re-decode");
        assert_eq!(v, v2);
    }

    // PathNotify: decode/encode/check — без паник на любом входе.
    if let Ok(v) = PathNotify::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&v));
        v.encode(&mut out).expect("encode");
        let v2 = PathNotify::decode(&out).expect("re-decode");
        assert_eq!(v, v2);
        let _ = v.check();
    }

    // PathBroken roundtrip.
    if let Ok(v) = PathBroken::decode(data) {
        let mut out = Vec::with_capacity(WireEncodable::size(&v));
        v.encode(&mut out).expect("encode");
        let v2 = PathBroken::decode(&out).expect("re-decode");
        assert_eq!(v, v2);
    }
});
