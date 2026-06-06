//! Inference Router (§17.1): routes `effect://inference/*` to a concrete model
//! backend by group policy, modality/capability filtering, retry, and fallback.
//!
//! Routing flow (§17.1):
//! ```text
//! match rule → group → filter models by request modality & capabilities
//!   → pick by group policy (Priority/RoundRobin/Latency/Weighted)
//!   → call backend → retry on 429/5xx → whole-group failure → fallback group
//!   → update stats
//! ```
//!
//! Config lives in `state://kernel/inference/{backends,models,groups}` and
//! `state://kernel/routing/inference` (§17.1). The [`Router`] here is the
//! in-process selection engine; the daemon loads config into it and registers
//! real backends. The offline baseline registers a single [`EchoBackend`] model.

use crate::inference::{InferenceBackend, ModelCapabilities, RequestRequirements};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// How a group picks among its candidate models (§17.1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GroupPolicy {
    /// Always the highest-priority (lowest index) healthy candidate.
    #[default]
    Priority,
    /// Rotate through candidates evenly.
    RoundRobin,
    /// Prefer the candidate with the lowest observed average latency.
    Latency,
    /// Weighted random by each model's weight.
    Weighted,
}

/// One registered model: a backend plus its routing metadata (§17.1).
pub struct ModelEntry {
    /// Stable `<backend>/<model_id>` qualified name.
    pub id: String,
    pub backend: Arc<dyn InferenceBackend>,
    pub caps: ModelCapabilities,
    /// Relative weight for [`GroupPolicy::Weighted`] (and a Priority tiebreak).
    pub weight: u32,
    /// Rolling stats for Latency policy and health.
    stats: ModelStats,
}

#[derive(Default)]
struct ModelStats {
    calls: AtomicU64,
    total_latency_micros: AtomicU64,
    failures: AtomicU64,
}

impl ModelEntry {
    pub fn new(id: impl Into<String>, backend: Arc<dyn InferenceBackend>) -> Self {
        let caps = backend.capabilities();
        Self {
            id: id.into(),
            backend,
            caps,
            weight: 1,
            stats: ModelStats::default(),
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }

    fn avg_latency_micros(&self) -> u64 {
        let calls = self.stats.calls.load(Ordering::Relaxed);
        if calls == 0 {
            return 0;
        }
        self.stats.total_latency_micros.load(Ordering::Relaxed) / calls
    }

    fn record(&self, latency_micros: u64, ok: bool) {
        self.stats.calls.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_latency_micros
            .fetch_add(latency_micros, Ordering::Relaxed);
        if !ok {
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A named set of candidate models with a selection policy and an optional
/// fallback group (§17.1).
pub struct ModelGroup {
    pub name: String,
    pub policy: GroupPolicy,
    /// Indices into [`Router::models`].
    pub members: Vec<usize>,
    /// Group to escalate to when every member fails (§17.1).
    pub fallback: Option<String>,
    /// Round-robin cursor (for [`GroupPolicy::RoundRobin`]).
    rr_cursor: AtomicU64,
}

impl ModelGroup {
    pub fn new(name: impl Into<String>, policy: GroupPolicy, members: Vec<usize>) -> Self {
        Self {
            name: name.into(),
            policy,
            members,
            fallback: None,
            rr_cursor: AtomicU64::new(0),
        }
    }

    pub fn with_fallback(mut self, group: impl Into<String>) -> Self {
        self.fallback = Some(group.into());
        self
    }
}

/// The routing engine (§17.1). Holds models and groups; selects and invokes a
/// backend with retry + fallback. Cheap to share; selection is lock-light.
pub struct Router {
    models: Vec<ModelEntry>,
    groups: HashMap<String, ModelGroup>,
    /// The group used when a request names none (the routing default rule).
    default_group: String,
    /// Max attempts per model on retryable (429/5xx-class) errors (§17.1).
    max_retries: u32,
    /// Weighted-policy RNG state (deterministic, seeded per Router).
    rng: Mutex<u64>,
}

/// The result of routing: which model handled it and its output.
pub struct Routed {
    pub model_id: String,
    pub output: nexus_types::Value,
}

impl Router {
    /// A router with one group `default` over the given models in priority order.
    pub fn new(models: Vec<ModelEntry>) -> Self {
        let member_idx: Vec<usize> = (0..models.len()).collect();
        let mut groups = HashMap::new();
        groups.insert(
            "default".to_string(),
            ModelGroup::new("default", GroupPolicy::Priority, member_idx),
        );
        Self {
            models,
            groups,
            default_group: "default".into(),
            max_retries: 2,
            rng: Mutex::new(0x2545_F491_4F6C_DD1D),
        }
    }

    /// The single-backend offline baseline ([`EchoBackend`]).
    pub fn baseline() -> Self {
        Self::new(vec![ModelEntry::new(
            "baseline/echo",
            Arc::new(crate::inference::EchoBackend),
        )])
    }

    /// Register an additional group (e.g. a fallback or modality-specific group).
    pub fn add_group(&mut self, group: ModelGroup) {
        self.groups.insert(group.name.clone(), group);
    }

    pub fn set_default_group(&mut self, name: impl Into<String>) {
        self.default_group = name.into();
    }

    pub fn set_max_retries(&mut self, n: u32) {
        self.max_retries = n;
    }

    /// Route an `infer` call (§17.1): pick a group, filter by requirements, pick
    /// a model by policy, call with retry, and on whole-group failure escalate to
    /// the fallback group. `requirements` gates which models are candidates.
    pub async fn infer(
        &self,
        input: &nexus_types::Value,
        requirements: &RequestRequirements,
        group: Option<&str>,
    ) -> Result<Routed, String> {
        let start = group.unwrap_or(&self.default_group).to_string();
        self.route(&start, input, requirements, &mut Vec::new())
            .await
    }

    /// Embed routes the same way but calls `embed` on the chosen model.
    pub async fn embed(
        &self,
        input: &nexus_types::Value,
        requirements: &RequestRequirements,
    ) -> Result<Routed, String> {
        // Embedding has no group escalation subtlety in the baseline: pick from
        // the default group's candidates and call embed with retry.
        let candidates = self.candidates(&self.default_group, requirements);
        if candidates.is_empty() {
            return Err("no model satisfies the embed request's modality".into());
        }
        let mut last_err = String::new();
        for &idx in &candidates {
            match self.call_embed(idx, input).await {
                Ok(v) => {
                    return Ok(Routed {
                        model_id: self.models[idx].id.clone(),
                        output: v,
                    });
                }
                Err(e) => last_err = e,
            }
        }
        Err(format!("all embed candidates failed: {last_err}"))
    }

    fn route<'a>(
        &'a self,
        group_name: &'a str,
        input: &'a nexus_types::Value,
        requirements: &'a RequestRequirements,
        visited: &'a mut Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Routed, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if visited.iter().any(|g| g == group_name) {
                return Err(format!("routing cycle through group '{group_name}'"));
            }
            visited.push(group_name.to_string());

            let candidates = self.candidates(group_name, requirements);
            // Try each candidate (ordered by the group policy) with per-model
            // retry; if the whole group fails, escalate to its fallback.
            let mut last_err = format!("no model in group '{group_name}' satisfies the request");
            for idx in self.order_candidates(group_name, &candidates) {
                match self.call_infer_with_retry(idx, input).await {
                    Ok(v) => {
                        return Ok(Routed {
                            model_id: self.models[idx].id.clone(),
                            output: v,
                        });
                    }
                    Err(e) => last_err = e,
                }
            }
            // Whole group failed → fallback (§17.1).
            if let Some(group) = self.groups.get(group_name)
                && let Some(fallback) = &group.fallback
            {
                return self.route(fallback, input, requirements, visited).await;
            }
            Err(last_err)
        })
    }

    /// The members of `group` whose capabilities satisfy `requirements`.
    fn candidates(&self, group: &str, req: &RequestRequirements) -> Vec<usize> {
        let Some(g) = self.groups.get(group) else {
            return Vec::new();
        };
        g.members
            .iter()
            .copied()
            .filter(|&i| self.models[i].caps.satisfies(req))
            .collect()
    }

    /// Order candidates by the group's policy (§17.1).
    fn order_candidates(&self, group: &str, candidates: &[usize]) -> Vec<usize> {
        let Some(g) = self.groups.get(group) else {
            return candidates.to_vec();
        };
        let mut ordered = candidates.to_vec();
        match g.policy {
            GroupPolicy::Priority => { /* already in member (priority) order */ }
            GroupPolicy::RoundRobin => {
                let len = ordered.len();
                if len > 0 {
                    let n = g.rr_cursor.fetch_add(1, Ordering::Relaxed) as usize;
                    ordered.rotate_left(n % len);
                }
            }
            GroupPolicy::Latency => {
                ordered.sort_by_key(|&i| self.models[i].avg_latency_micros());
            }
            GroupPolicy::Weighted => {
                ordered = self.weighted_order(&ordered);
            }
        }
        ordered
    }

    /// Deterministic weighted ordering: repeatedly pick by weight without
    /// replacement (xorshift RNG, seeded per Router → reproducible).
    fn weighted_order(&self, candidates: &[usize]) -> Vec<usize> {
        let mut pool: Vec<usize> = candidates.to_vec();
        let mut out = Vec::with_capacity(pool.len());
        let mut rng = self.rng.lock();
        while !pool.is_empty() {
            let total: u64 = pool.iter().map(|&i| self.models[i].weight as u64).sum();
            *rng ^= *rng << 13;
            *rng ^= *rng >> 7;
            *rng ^= *rng << 17;
            let mut pick = *rng % total.max(1);
            let mut chosen = 0usize;
            for (pos, &i) in pool.iter().enumerate() {
                let w = self.models[i].weight as u64;
                if pick < w {
                    chosen = pos;
                    break;
                }
                pick -= w;
            }
            out.push(pool.remove(chosen));
        }
        out
    }

    async fn call_infer_with_retry(
        &self,
        idx: usize,
        input: &nexus_types::Value,
    ) -> Result<nexus_types::Value, String> {
        let model = &self.models[idx];
        let mut last_err = String::new();
        for attempt in 0..=self.max_retries {
            let t0 = std::time::Instant::now();
            match model.backend.infer(input).await {
                Ok(v) => {
                    model.record(t0.elapsed().as_micros() as u64, true);
                    return Ok(v);
                }
                Err(e) => {
                    model.record(t0.elapsed().as_micros() as u64, false);
                    last_err = e;
                    // Only retry transient (429/5xx-class) errors; permanent
                    // errors fail fast so we move to the next model.
                    if !is_retryable(&last_err) || attempt == self.max_retries {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }

    async fn call_embed(
        &self,
        idx: usize,
        input: &nexus_types::Value,
    ) -> Result<nexus_types::Value, String> {
        let model = &self.models[idx];
        let t0 = std::time::Instant::now();
        let r = model.backend.embed(input).await;
        model.record(t0.elapsed().as_micros() as u64, r.is_ok());
        r
    }
}

/// Whether a backend error is transient and worth retrying (§17.1: 429/5xx).
/// Backends report errors as strings; we match the conventional markers.
fn is_retryable(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("429")
        || e.contains("rate limit")
        || e.contains("rate_limit")
        || e.contains("timeout")
        || e.contains("timed out")
        || e.contains("503")
        || e.contains("502")
        || e.contains("500")
        || e.contains("overloaded")
        || e.contains("unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use nexus_types::Value;
    use std::sync::atomic::AtomicU32;

    struct CountingBackend {
        label: &'static str,
        calls: Arc<AtomicU32>,
        fail_with: Option<String>,
    }
    #[async_trait]
    impl InferenceBackend for CountingBackend {
        async fn infer(&self, _input: &Value) -> Result<Value, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.fail_with {
                Some(e) => Err(e.clone()),
                None => Ok(Value::Str(self.label.into())),
            }
        }
        async fn embed(&self, _input: &Value) -> Result<Value, String> {
            Ok(Value::Str(self.label.into()))
        }
    }

    fn model(
        id: &str,
        label: &'static str,
        calls: Arc<AtomicU32>,
        fail: Option<&str>,
    ) -> ModelEntry {
        ModelEntry::new(
            id,
            Arc::new(CountingBackend {
                label,
                calls,
                fail_with: fail.map(String::from),
            }),
        )
    }

    #[tokio::test]
    async fn priority_picks_first_healthy() {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            model("p/a", "a", c0.clone(), None),
            model("p/b", "b", c1.clone(), None),
        ]);
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .unwrap();
        assert_eq!(out.model_id, "p/a");
        assert_eq!(c0.load(Ordering::SeqCst), 1);
        assert_eq!(
            c1.load(Ordering::SeqCst),
            0,
            "second model not consulted when first succeeds"
        );
    }

    #[tokio::test]
    async fn retries_then_falls_through_to_next_model() {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            // First model fails with a retryable error: tried max_retries+1 times.
            model("p/a", "a", c0.clone(), Some("HTTP 503 unavailable")),
            model("p/b", "b", c1.clone(), None),
        ]);
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .unwrap();
        assert_eq!(out.model_id, "p/b", "falls through to the healthy model");
        assert_eq!(
            c0.load(Ordering::SeqCst),
            3,
            "retried 429/5xx: 1 + 2 retries"
        );
    }

    #[tokio::test]
    async fn permanent_error_is_not_retried() {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            model("p/a", "a", c0.clone(), Some("invalid api key")),
            model("p/b", "b", c1.clone(), None),
        ]);
        let _ = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .unwrap();
        assert_eq!(
            c0.load(Ordering::SeqCst),
            1,
            "permanent error fails fast, no retry"
        );
    }

    #[tokio::test]
    async fn fallback_group_on_whole_group_failure() {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let mut r = Router::new(vec![
            model("primary/a", "a", c0.clone(), Some("invalid request")),
            model("backup/b", "b", c1.clone(), None),
        ]);
        // Group `primary` = [0] with fallback `backup` = [1]; default = primary.
        r.add_group(
            ModelGroup::new("primary", GroupPolicy::Priority, vec![0]).with_fallback("backup"),
        );
        r.add_group(ModelGroup::new("backup", GroupPolicy::Priority, vec![1]));
        r.set_default_group("primary");
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .unwrap();
        assert_eq!(out.model_id, "backup/b", "escalated to fallback group");
    }

    #[tokio::test]
    async fn modality_filter_excludes_incapable_models() {
        // The only model supports text; an image request finds no candidate.
        let c0 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![model("p/text", "t", c0, None)]);
        let req = RequestRequirements {
            needs_vision: true,
            ..Default::default()
        };
        assert!(r.infer(&Value::Null, &req, None).await.is_err());
    }
}
