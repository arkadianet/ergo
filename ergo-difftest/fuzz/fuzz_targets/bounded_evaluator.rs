#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| ergo_difftest::execution_fuzz::fuzz_bounded_evaluator(data));
