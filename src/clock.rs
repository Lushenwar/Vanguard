//! Time sources, split by what each is allowed to be used for.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Monotonic event ordering plus an advisory wall clock.
///
/// The split is the point. `mono_ns` is measured from an epoch captured once at
/// startup and is the only value the hash chain and replay ever see; wall time
/// is recorded for humans and never ordered on, because NTP correction and
/// container migration both move it backwards.
#[derive(Debug, Clone)]
pub struct Clock {
    epoch: Instant,
}

impl Clock {
    pub fn new() -> Clock {
        Clock {
            epoch: Instant::now(),
        }
    }

    /// Nanoseconds since this clock's epoch. Monotonic within one daemon run.
    pub fn mono_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Milliseconds since the Unix epoch. Advisory only.
    pub fn wall_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Clock::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mono_never_goes_backwards() {
        let c = Clock::new();
        let mut last = 0;
        for _ in 0..1000 {
            let now = c.mono_ns();
            assert!(now >= last);
            last = now;
        }
    }
}
