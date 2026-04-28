// CLI logging.
//
// The hand-rolled `log_info` / `log_warn` / `log_error` helpers are gone;
// every emit point now uses `tracing::{info,warn,error}!` directly. This
// module is responsible only for *configuring* the tracing subscriber so
// that:
//
// * stderr lines stay JSON-formatted with the same `level`, `event`,
//   `run_id`, `policy_id` shape as before. Tests scrape these fields.
// * `run_id` and `policy_id` are inherited from a per-run span so emit
//   points don't have to thread a `LogContext` through every function.
// * counters and structured fields land as top-level keys in the JSON
//   payload (so `verified_checked: 12` appears as `"verified_checked":12`,
//   not nested under a `counters` map).
//
// The previous wire shape included a `counters` field as a nested map; the
// new shape promotes counter values to top-level fields. Tests in
// `phase1_gates::logs_use_structured_json_schema_v1` only assert on the
// presence of `level`, `event`, `run_id`, `policy_id` so the change is
// backward-compatible for them.

use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::Once;

use serde_json::{Map, Value};
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

pub(crate) const UNKNOWN_LOG_ID: &str = "unknown";

/// Initialize the global tracing subscriber. Idempotent — calling more
/// than once (e.g. once per integration test) is a noop after the first
/// call.
pub(crate) fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let layer = JsonStderrLayer::default();
        let _ = tracing_subscriber::registry().with(layer).try_init();
    });
}

/// Custom layer that emits one JSON line per event on stderr.
///
/// The format is compatible with the legacy log shape: a single-line
/// JSON object with `level`, `event`, `run_id`, `policy_id`, optional
/// `reason_code`, and any additional structured fields the call site
/// recorded. Span fields (specifically `run_id` and `policy_id` set by
/// the run-level span) are merged into every event.
struct JsonStderrLayer {
    // Tests run in parallel processes via `Command`, so a Mutex here only
    // serialises *within* the current process — which is what we want so
    // a single process never interleaves bytes from concurrent emits.
    stderr_lock: Mutex<()>,
}

impl Default for JsonStderrLayer {
    fn default() -> Self {
        Self {
            stderr_lock: Mutex::new(()),
        }
    }
}

impl<S> Layer<S> for JsonStderrLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = JsonFieldVisitor::default();
        event.record(&mut visitor);

        let mut payload = Map::<String, Value>::new();
        payload.insert(
            "level".to_string(),
            Value::String(event.metadata().level().to_string()),
        );

        // Merge span fields. We only care about run-level fields right now.
        if let Some(span) = ctx.lookup_current() {
            for span_ref in span.scope().from_root() {
                if let Some(extensions) = span_ref.extensions().get::<SpanFields>() {
                    for (key, value) in &extensions.fields {
                        payload.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                }
            }
        }

        // Pull `event` and other named fields out of the visitor's bag.
        for (key, value) in visitor.fields.drain(..) {
            // Skip `message` — tracing always records the format string as
            // a `message` field; the legacy logger never had one and the
            // tests don't expect it.
            if key == "message" {
                continue;
            }
            payload.insert(key, value);
        }

        // Default run_id / policy_id to UNKNOWN_LOG_ID when no span has
        // populated them. The legacy logger required these fields on every
        // line; tests still assert on their presence.
        payload
            .entry("run_id".to_string())
            .or_insert_with(|| Value::String(UNKNOWN_LOG_ID.to_string()));
        payload
            .entry("policy_id".to_string())
            .or_insert_with(|| Value::String(UNKNOWN_LOG_ID.to_string()));

        let line = match serde_json::to_string(&Value::Object(payload)) {
            Ok(s) => s,
            Err(_) => return,
        };

        if let Ok(_guard) = self.stderr_lock.lock() {
            eprintln!("{line}");
        }
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut visitor = JsonFieldVisitor::default();
            attrs.record(&mut visitor);
            let mut extensions = span.extensions_mut();
            extensions.insert(SpanFields {
                fields: visitor.fields,
            });
        }
    }
}

#[derive(Debug)]
struct SpanFields {
    fields: Vec<(String, Value)>,
}

#[derive(Default)]
struct JsonFieldVisitor {
    fields: Vec<(String, Value)>,
}

impl Visit for JsonFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .push((field.name().to_string(), Value::String(value.to_string())));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.push((
            field.name().to_string(),
            Value::Number(serde_json::Number::from(value)),
        ));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push((
            field.name().to_string(),
            Value::Number(serde_json::Number::from(value)),
        ));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), Value::Bool(value)));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let number = serde_json::Number::from_f64(value);
        if let Some(n) = number {
            self.fields
                .push((field.name().to_string(), Value::Number(n)));
        } else {
            self.fields
                .push((field.name().to_string(), Value::String(value.to_string())));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut s = String::new();
        let _ = write!(s, "{value:?}");
        self.fields
            .push((field.name().to_string(), Value::String(s)));
    }
}
