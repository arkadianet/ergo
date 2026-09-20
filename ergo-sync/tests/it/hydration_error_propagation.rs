//! Pins that `HydrationError::Store` carries a structured
//! `StateError`, not a flattened `String`. The Phase 3 / Phase 4
//! taxonomy work hinges on operators being able to downcast at crate
//! seams without parsing Display text; this test would fail at
//! compile time if `Store` ever regresses to `Store(String)`.

use ergo_state::store::StateError;
use ergo_sync::executor::HydrationError;

// ----- happy path -----

#[test]
fn from_state_error_routes_through_store_variant() {
    // The `#[from] StateError` annotation generates this conversion;
    // pin it so a future enum re-shuffle that drops the attribute or
    // re-routes the conversion to another variant fails loudly here
    // instead of silently flipping operator-visible error categories.
    let inner = StateError::InternalInvariant {
        what: "test-only marker",
    };
    let hyd: HydrationError = inner.into();
    assert!(matches!(hyd, HydrationError::Store(_)));
}

// ----- error paths -----

#[test]
fn store_variant_preserves_concrete_state_error_variant() {
    // The phase-3-4 migration claims operators can pattern-match on
    // the underlying StateError. Construct a known variant, propagate
    // through the From boundary, then drill into it. If anyone later
    // flattens `Store` back to `String` the destructuring fails at
    // compile time.
    let inner = StateError::InvalidPrecondition {
        what: "phase-4a propagation pin",
    };
    let hyd: HydrationError = inner.into();
    let HydrationError::Store(extracted) = hyd else {
        panic!("expected HydrationError::Store, From regressed");
    };
    assert!(
        matches!(
            extracted,
            StateError::InvalidPrecondition {
                what: "phase-4a propagation pin"
            }
        ),
        "inner StateError variant must survive intact, got {extracted:?}",
    );
}

#[test]
fn question_mark_propagation_through_from_compiles_and_routes() {
    // The migration replaced `.map_err(|e| HydrationError::Store(format!(...)))?`
    // with bare `?`. Sanity-check that the `?` path picks
    // `From<StateError> for HydrationError` and routes through Store,
    // not some other auto-derived conversion that might appear later.
    fn propagate() -> Result<(), HydrationError> {
        fn inner() -> Result<(), StateError> {
            Err(StateError::InvalidPrecondition {
                what: "question-mark routing pin",
            })
        }
        inner()?;
        Ok(())
    }
    let err = propagate().expect_err("inner returns Err");
    let HydrationError::Store(StateError::InvalidPrecondition { what }) = err else {
        panic!("expected Store(InvalidPrecondition), got {err:?}");
    };
    assert_eq!(what, "question-mark routing pin");
}
