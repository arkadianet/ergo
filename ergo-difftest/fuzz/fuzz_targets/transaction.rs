#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ergo_difftest::fuzz::fuzz_one("transaction", data);
});
