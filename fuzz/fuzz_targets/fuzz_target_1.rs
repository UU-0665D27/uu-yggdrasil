#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    uu_yggdrasil::ironwood::types::packetconn::fuzz::fuzz_handle_conn(data);
});
