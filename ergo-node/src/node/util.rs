//! Tiny utilities reused by the node runtime — session-id generation
//! and address-book wall-to-monotonic time translation.

use std::time::{Instant, SystemTime};

pub(super) fn rand_session_id() -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    h.finish() as i64
}

/// Convert a wall-clock `SystemTime` to a monotonic `Instant` anchored on
/// `(mono_now, wall_now)` captured at restore time. Used to translate the
/// address book's persisted timestamps into the in-memory `Instant`-based
/// dial pool. Future-stamped records (clock skew or system time jumped
/// backwards since persistence) clamp to `mono_now` so backoff windows
/// don't get stuck waiting for a past time.
pub(super) fn wall_to_instant(
    target: SystemTime,
    mono_now: Instant,
    wall_now: SystemTime,
) -> Instant {
    match wall_now.duration_since(target) {
        Ok(elapsed) => mono_now.checked_sub(elapsed).unwrap_or(mono_now),
        Err(_) => mono_now,
    }
}
