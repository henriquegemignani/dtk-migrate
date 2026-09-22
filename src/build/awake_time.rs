//! Elapsed working time for candidate deadlines.
//!
//! Windows `Instant` advances while the computer sleeps. A command can cross a
//! suspend and appear to exceed its trial bound on wake even though it used no
//! CPU or linker time. Keep the timeout budget and its log on the same clock.

use std::time::Duration;
#[cfg(not(windows))]
use std::time::Instant;

#[derive(Clone, Copy)]
pub struct AwakeInstant {
    #[cfg(windows)]
    ticks: u64,
    #[cfg(not(windows))]
    instant: Instant,
}

impl AwakeInstant {
    pub fn now() -> Self {
        #[cfg(windows)]
        {
            let mut ticks = 0;
            // SAFETY: the pointer is valid and the API writes one u64.
            unsafe {
                windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise(
                    &mut ticks,
                );
            }
            Self { ticks }
        }
        #[cfg(not(windows))]
        {
            Self { instant: Instant::now() }
        }
    }

    pub fn elapsed(self) -> Duration {
        #[cfg(windows)]
        {
            // Unbiased interrupt time is in 100 ns units and excludes sleep.
            Duration::from_nanos(Self::now().ticks.saturating_sub(self.ticks).saturating_mul(100))
        }
        #[cfg(not(windows))]
        {
            self.instant.elapsed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_working_time_advances_while_awake() {
        let start = AwakeInstant::now();
        std::thread::sleep(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(10));
    }
}
