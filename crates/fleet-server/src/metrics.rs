//! Process metrics in the Prometheus text format, served on the separate,
//! unauthenticated `FLEET_METRICS_BIND` listener. Labels carry only status
//! classes, decision kinds, and deny-reason codes, never identifiers.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use actix_web::{HttpResponse, web};

#[derive(Default)]
pub struct Metrics {
    requests: [AtomicU64; 5],
    request_seconds_micros: AtomicU64,
    auth_failures: AtomicU64,
    rate_limited: AtomicU64,
    audit_events: AtomicU64,
    audit_sequence: AtomicU64,
    decisions: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
}

pub static METRICS: std::sync::LazyLock<Metrics> = std::sync::LazyLock::new(Metrics::default);

impl Metrics {
    pub fn request(&self, status: u16, micros: u64) {
        let class = usize::from((status / 100).clamp(1, 5)) - 1;
        self.requests[class].fetch_add(1, Ordering::Relaxed);
        self.request_seconds_micros
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn audit_appended(&self, sequence: u64) {
        self.audit_events.fetch_add(1, Ordering::Relaxed);
        self.audit_head(sequence);
    }

    /// Raises the audit head gauge, for example from the database at startup.
    pub fn audit_head(&self, sequence: u64) {
        self.audit_sequence.fetch_max(sequence, Ordering::Relaxed);
    }

    /// One authorization decision: `allow`, or `deny` with its reason code.
    pub fn decision(&self, decision: &'static str, reason: &'static str) {
        *self
            .decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry((decision, reason))
            .or_default() += 1;
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "# HELP fleet_http_requests_total HTTP requests by status class."
        );
        let _ = writeln!(out, "# TYPE fleet_http_requests_total counter");
        let mut total = 0;
        for (index, class) in ["1xx", "2xx", "3xx", "4xx", "5xx"].iter().enumerate() {
            let count = load(&self.requests[index]);
            total += count;
            let _ = writeln!(
                out,
                "fleet_http_requests_total{{class=\"{class}\"}} {count}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP fleet_http_request_duration_seconds Total time spent serving requests."
        );
        let _ = writeln!(out, "# TYPE fleet_http_request_duration_seconds summary");
        #[allow(clippy::cast_precision_loss)]
        let seconds = load(&self.request_seconds_micros) as f64 / 1_000_000.0;
        let _ = writeln!(out, "fleet_http_request_duration_seconds_sum {seconds}");
        let _ = writeln!(out, "fleet_http_request_duration_seconds_count {total}");
        for (name, help, counter) in [
            (
                "fleet_auth_failures_total",
                "Rejected bearer tokens.",
                &self.auth_failures,
            ),
            (
                "fleet_rate_limited_total",
                "Requests refused by a rate limit.",
                &self.rate_limited,
            ),
            (
                "fleet_audit_events_total",
                "Audit events appended by this process.",
                &self.audit_events,
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {}", load(counter));
        }
        let _ = writeln!(
            out,
            "# HELP fleet_audit_sequence Highest audit sequence in the chain."
        );
        let _ = writeln!(out, "# TYPE fleet_audit_sequence gauge");
        let _ = writeln!(out, "fleet_audit_sequence {}", load(&self.audit_sequence));
        let _ = writeln!(
            out,
            "# HELP fleet_authorization_decisions_total Per-request grant decisions."
        );
        let _ = writeln!(out, "# TYPE fleet_authorization_decisions_total counter");
        for ((decision, reason), count) in self
            .decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            let _ = writeln!(
                out,
                "fleet_authorization_decisions_total{{decision=\"{decision}\",reason=\"{reason}\"}} {count}"
            );
        }
        out
    }
}

pub async fn serve_metrics() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .body(METRICS.render())
}

pub fn configure(config: &mut web::ServiceConfig) {
    config.route("/metrics", web::get().to(serve_metrics));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_without_identifiers() {
        let metrics = Metrics::default();
        metrics.request(200, 1_500_000);
        metrics.request(404, 500_000);
        metrics.decision("deny", "stale_policy");
        metrics.decision("allow", "none");
        metrics.audit_appended(7);
        let text = metrics.render();
        assert!(text.contains("fleet_http_requests_total{class=\"2xx\"} 1"));
        assert!(text.contains("fleet_http_requests_total{class=\"4xx\"} 1"));
        assert!(text.contains("fleet_http_request_duration_seconds_sum 2"));
        assert!(text.contains("fleet_http_request_duration_seconds_count 2"));
        assert!(text.contains(
            "fleet_authorization_decisions_total{decision=\"deny\",reason=\"stale_policy\"} 1"
        ));
        assert!(text.contains("fleet_audit_sequence 7"));
    }
}
