#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    uu_yggdrasil::ironwood::signed::fuzz::fuzz_unpack(data);
});
