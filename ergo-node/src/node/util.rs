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

/// Ban expiries are future timestamps, unlike dial-history timestamps. Keep the
/// remaining TTL across restart instead of clamping every live ban to "now".
pub(super) fn ban_expiry_to_instant(
    target: SystemTime,
    mono_now: Instant,
    wall_now: SystemTime,
) -> Instant {
    match target.duration_since(wall_now) {
        Ok(remaining) => mono_now
            .checked_add(remaining.min(std::time::Duration::from_secs(365 * 24 * 3600)))
            .unwrap_or_else(|| mono_now + std::time::Duration::from_secs(365 * 24 * 3600)),
        Err(_) => mono_now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn restored_ban_ttl_is_capped_when_wall_clock_moves_backwards() {
        let mono = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        assert_eq!(
            ban_expiry_to_instant(wall + Duration::from_secs(10 * 365 * 86400), mono, wall),
            mono + Duration::from_secs(365 * 86400)
        );
    }

    #[test]
    fn ban_restore_keeps_future_ttl_while_dial_history_clamps_future_dates() {
        let mono = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let future = wall + Duration::from_secs(3600);
        assert_eq!(
            ban_expiry_to_instant(future, mono, wall),
            mono + Duration::from_secs(3600)
        );
        assert_eq!(
            ban_expiry_to_instant(wall - Duration::from_secs(1), mono, wall),
            mono
        );
        assert_eq!(wall_to_instant(future, mono, wall), mono);
    }
}
