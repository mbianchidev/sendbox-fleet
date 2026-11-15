//! In-process token-bucket rate limits.
//!
//! - Every authenticated principal may make `FLEET_RATE_LIMIT_PER_MINUTE`
//!   `/v1` requests per minute (burst of the same size).
//! - Every peer address may fail authentication
//!   `FLEET_AUTH_FAILURES_PER_MINUTE` times per minute; once exhausted, its
//!   requests are refused before any token is checked.
//!
//! Limits are per process. Behind a reverse proxy, every client shares the
//! proxy's address for the failure limit, so also limit at the proxy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entries idle this long are dropped when the table grows.
const IDLE: Duration = Duration::from_secs(10 * 60);
const PRUNE_ABOVE: usize = 10_000;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub struct RateLimiter {
    per_minute: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// `per_minute == 0` disables the limit.
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refill(&self, bucket: &mut Bucket, now: Instant) {
        let rate = f64::from(self.per_minute) / 60.0;
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(f64::from(self.per_minute));
        bucket.updated = now;
    }

    /// Seconds to wait when `key` has no budget left, without spending any.
    pub fn exhausted(&self, key: &str, now: Instant) -> Option<u64> {
        if self.per_minute == 0 {
            return None;
        }
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bucket = buckets.get_mut(key)?;
        self.refill(bucket, now);
        (bucket.tokens < 1.0).then(|| self.retry_after(bucket.tokens))
    }

    /// Spends one unit for `key`, or returns the seconds to wait.
    pub fn spend(&self, key: &str, now: Instant) -> Result<(), u64> {
        if self.per_minute == 0 {
            return Ok(());
        }
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() > PRUNE_ABOVE {
            buckets.retain(|_, bucket| now.saturating_duration_since(bucket.updated) < IDLE);
        }
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: f64::from(self.per_minute),
            updated: now,
        });
        self.refill(bucket, now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(self.retry_after(bucket.tokens))
        }
    }

    fn retry_after(&self, tokens: f64) -> u64 {
        let rate = f64::from(self.per_minute) / 60.0;
        // Truncation is fine: the value is a small positive wait in seconds.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let seconds = ((1.0 - tokens) / rate).ceil() as u64;
        seconds.max(1)
    }
}

/// Both limits, shared through application data.
pub struct Limits {
    pub requests: RateLimiter,
    pub auth_failures: RateLimiter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_over_time_and_zero_disables() {
        let limiter = RateLimiter::new(2);
        let start = Instant::now();
        assert!(limiter.spend("a", start).is_ok());
        assert!(limiter.spend("a", start).is_ok());
        let wait = limiter.spend("a", start).unwrap_err();
        assert_eq!(wait, 30);
        assert!(limiter.spend("b", start).is_ok(), "keys are independent");
        assert_eq!(limiter.exhausted("a", start), Some(30));
        assert!(limiter.exhausted("c", start).is_none());
        assert!(limiter.spend("a", start + Duration::from_secs(30)).is_ok());

        let unlimited = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(unlimited.spend("a", start).is_ok());
        }
    }
}
