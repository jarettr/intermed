//! Process-wide output verbosity for informational stderr messages.
//!
//! `--quiet` / `--verbose` set a single level once at startup; the rest of the CLI
//! reads it through [`info!`] / [`detail!`] (gated `eprintln!`s) so progress chatter
//! can be silenced for scripting or expanded for debugging. Errors are never gated —
//! they always print regardless of level.

use std::sync::atomic::{AtomicU8, Ordering};

/// Suppress all informational output; only errors print.
pub const QUIET: u8 = 0;
/// Default: high-level progress notes.
pub const NORMAL: u8 = 1;
/// `-v`: extra detail (rule provenance, per-phase notes).
pub const VERBOSE: u8 = 2;

static LEVEL: AtomicU8 = AtomicU8::new(NORMAL);

/// Set the global level. `quiet` wins over `verbose`; otherwise level is
/// `NORMAL + verbose` (so `-v` → VERBOSE, `-vv` → 3, …).
pub fn configure(quiet: bool, verbose: u8) {
    let level = if quiet {
        QUIET
    } else {
        NORMAL.saturating_add(verbose)
    };
    LEVEL.store(level, Ordering::Relaxed);
}

/// Current verbosity level.
#[must_use]
pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

/// True when informational (`NORMAL`) messages should be shown.
#[must_use]
pub fn is_normal() -> bool {
    level() >= NORMAL
}

/// True when verbose (`-v`) detail should be shown.
#[must_use]
pub fn is_verbose() -> bool {
    level() >= VERBOSE
}

/// Print an informational message to stderr unless `--quiet`.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::verbosity::is_normal() {
            eprintln!($($arg)*);
        }
    };
}

/// Print verbose detail to stderr only at `-v` or higher.
#[macro_export]
macro_rules! detail {
    ($($arg:tt)*) => {
        if $crate::verbosity::is_verbose() {
            eprintln!($($arg)*);
        }
    };
}
