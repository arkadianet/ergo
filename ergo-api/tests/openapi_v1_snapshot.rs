//! Snapshot of the v1 product-API `/api/v1/*` OpenAPI YAML.
//!
//! The derive in `v1::openapi` generates the spec from the handler
//! annotations and DTO `ToSchema` derives across
//! `crate::v1::{routes,accounts,operator,script,webhooks,realtime}`. This
//! test pins the generated YAML against a checked-in golden file so a
//! handler-signature or DTO change that isn't mirrored in the
//! `#[utoipa::path]` / `#[derive]` annotations fails loudly here instead
//! of silently shipping a wrong spec.
//!
//! A sibling, NOT a replacement, of `openapi_native_snapshot.rs` — the v1
//! product surface is a separate document from the pre-v1 native surface
//! (wallet/mining/votes/indexer/node); see `v1::openapi`'s module docs.
//!
//! Regenerate the golden file after an intentional spec change:
//!
//! ```text
//! cargo test -p ergo-api openapi_v1_snapshot -- --ignored --nocapture regenerate
//! ```

use ergo_api::v1::openapi::v1_openapi_yaml;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/openapi_v1.yaml"
);

// ----- happy path -----

#[test]
fn openapi_v1_matches_snapshot() {
    let actual = v1_openapi_yaml();

    // utoipa 5 emits OpenAPI 3.1 by default — pin the major.minor so a
    // dependency bump that changes the emitted version is caught here.
    assert!(
        actual.starts_with("openapi: 3.1."),
        "expected utoipa 5 default OpenAPI 3.1 emission, got first line: {:?}",
        actual.lines().next(),
    );

    let expected = std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|e| {
        panic!(
            "could not read golden file {FIXTURE_PATH}: {e}\n\
             Generate it with:\n  \
             cargo test -p ergo-api openapi_v1_snapshot -- --ignored --nocapture regenerate"
        )
    });

    if actual != expected {
        panic!(
            "v1 OpenAPI spec drifted from the checked-in golden file.\n{}\n\
             If this change is intentional, regenerate the golden file:\n  \
             cargo test -p ergo-api openapi_v1_snapshot -- --ignored --nocapture regenerate",
            first_difference(&expected, &actual),
        );
    }
}

// ----- regeneration tool -----

/// Rewrites the golden file from the current derive output. Ignored by
/// default so a normal `cargo test` run never mutates the fixture; run it
/// explicitly (see module docs) after an intentional spec change.
#[test]
#[ignore = "writes the golden fixture; run explicitly to regenerate after an intentional spec change"]
fn regenerate() {
    let actual = v1_openapi_yaml();
    std::fs::write(FIXTURE_PATH, &actual)
        .unwrap_or_else(|e| panic!("could not write golden file {FIXTURE_PATH}: {e}"));
    eprintln!("regenerated {FIXTURE_PATH} ({} bytes)", actual.len());
}

// ----- helpers -----

/// Compact "expected vs actual" report around the first differing line,
/// so a CI failure points straight at the drift rather than dumping the
/// whole document.
fn first_difference(expected: &str, actual: &str) -> String {
    for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
        if e != a {
            return format!(
                "first difference at line {}:\n  - expected: {e}\n  + actual:   {a}",
                i + 1,
            );
        }
    }
    let (elen, alen) = (expected.lines().count(), actual.lines().count());
    format!("content matches line-for-line up to the shorter file; line counts differ: expected {elen}, actual {alen}")
}
