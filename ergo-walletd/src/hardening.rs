//! Process hardening applied before any credential or secret is read.
//!
//! The unlocked master key lives in ordinary process memory. These measures
//! keep that memory out of core files, away from same-user debuggers, and
//! optionally out of swap. They complement, and do not replace, the systemd
//! unit's `LimitCORE=0` and `MemorySwapMax=0`.

/// Disable core dumps and, on Linux, mark the process non-dumpable, which
/// also stops same-user `ptrace` attachment and `/proc/<pid>/mem` reads.
pub fn disable_core_dumps() -> Result<(), String> {
    #[cfg(unix)]
    {
        use rustix::process::{setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|error| format!("disable core dumps: {error}"))?;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|error| format!("mark process non-dumpable: {error}"))?;
    Ok(())
}

/// Lock all current and future memory into RAM (Linux only). Refused unless
/// the memory-lock limit is unlimited: with a bounded limit, locking future
/// mappings would make later allocations fail instead of degrading.
pub fn lock_all_memory() -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::mm::{mlockall, MlockAllFlags};
        use rustix::process::{getrlimit, Resource};
        if getrlimit(Resource::Memlock).current.is_some() {
            return Err(
                "lock_memory requires an unlimited memory-lock limit (systemd: LimitMEMLOCK=infinity)"
                    .to_string(),
            );
        }
        mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE | MlockAllFlags::ONFAULT)
            .map_err(|error| format!("lock process memory: {error}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Err("lock_memory is supported on Linux only".to_string())
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    #[test]
    fn core_dumps_are_disabled_for_the_process() {
        super::disable_core_dumps().unwrap();
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
}
