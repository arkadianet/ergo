#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| ergo_difftest::network_fuzz::fuzz_handshake(data));
