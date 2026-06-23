//! Inference router for `effect://inference/*` model selection.

use crate::inference::{InferenceBackend, ModelCapabilities, RequestRequirements};
#[cfg(any(
    feature = "openai-responses",
    feature = "openai-chat",
    feature = "anthropic-messages",
    feature = "gemini-generate-content"
))]
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
enum RouteMethod {
    Infer,
    Embed,
    Rerank,
    Plan,
}

/// How a group picks among its candidate models.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum GroupPolicy {
    /// Always the highest-priority (lowest index) healthy candidate.
    #[default]
    Priority,
    /// Rotate through candidates evenly.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    RoundRobin,
    /// Prefer the candidate with the lowest observed average latency.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    Latency,
    /// Weighted random by each model's weight.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    Weighted,
}

/// One registered model: a backend plus its routing metadata.
pub(crate) struct ModelEntry {
    /// Stable `<backend>/<model_id>` qualified name.
    #[cfg(test)]
    pub(crate) id: String,
    /// Backend implementation that serves this model.
    pub(crate) backend: Arc<dyn InferenceBackend>,
    /// Capability declaration used for candidate filtering.
    pub(crate) caps: ModelCapabilities,
    /// Relative weight for [`GroupPolicy::Weighted`] (and a Priority tiebreak).
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) weight: u32,
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
    /// Create a model entry using the backend's declared capabilities.
    #[cfg(test)]
    pub(crate) fn new(id: impl Into<String>, backend: Arc<dyn InferenceBackend>) -> Self {
        let caps = backend.capabilities();
        Self {
            id: id.into(),
            backend,
            caps,
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            weight: 1,
            stats: ModelStats::default(),
        }
    }

    /// Create a model entry using the backend's declared capabilities.
    #[cfg(not(test))]
    pub(crate) fn new(_id: impl Into<String>, backend: Arc<dyn InferenceBackend>) -> Self {
        let caps = backend.capabilities();
        Self {
            backend,
            caps,
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            weight: 1,
            stats: ModelStats::default(),
        }
    }

    /// Set this model's routing weight.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }

    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
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
/// fallback group.
pub(crate) struct ModelGroup {
    /// Group name referenced by routing config or fallback.
    #[cfg(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) name: String,
    /// Selection policy used within this group.
    pub(crate) policy: GroupPolicy,
    /// Indices into the router's model table.
    pub(crate) members: Vec<usize>,
    /// Group to escalate to when every member fails.
    pub(crate) fallback: Option<String>,
    /// Round-robin cursor (for [`GroupPolicy::RoundRobin`]).
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    rr_cursor: AtomicU64,
}

impl ModelGroup {
    /// Create a model group over model-table member indices.
    #[cfg(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn new(name: impl Into<String>, policy: GroupPolicy, members: Vec<usize>) -> Self {
        Self {
            name: name.into(),
            policy,
            members,
            fallback: None,
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            rr_cursor: AtomicU64::new(0),
        }
    }

    /// Create a model group over model-table member indices.
    #[cfg(not(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    )))]
    pub(crate) fn new(_name: impl Into<String>, policy: GroupPolicy, members: Vec<usize>) -> Self {
        Self {
            policy,
            members,
            fallback: None,
        }
    }

    /// Set the fallback group used when all members fail.
    #[cfg(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn with_fallback(mut self, group: impl Into<String>) -> Self {
        self.fallback = Some(group.into());
        self
    }
}

/// The routing engine. Holds models and groups; selects and invokes a
/// backend with retry + fallback. Cheap to share; selection is lock-light.
pub(crate) struct Router {
    models: Vec<ModelEntry>,
    groups: HashMap<String, ModelGroup>,
    /// The group used when a request names none (the routing default rule).
    default_group: String,
    /// Max attempts per model on retryable (429/5xx-class) errors.
    max_retries: u32,
    /// Weighted-policy RNG state (deterministic, seeded per Router).
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    rng: Mutex<u64>,
}

/// The result of routing: which model handled it and its output.
pub(crate) struct Routed {
    /// Model id that handled the request.
    #[cfg(test)]
    pub(crate) model_id: String,
    /// Output returned by the selected model.
    pub(crate) output: xolotl_types::Value,
}

impl Router {
    /// A router with one group `default` over the given models in priority order.
    pub(crate) fn new(models: Vec<ModelEntry>) -> Self {
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
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            rng: Mutex::new(0x2545_F491_4F6C_DD1D),
        }
    }

    #[cfg(test)]
    fn routed(&self, idx: usize, output: xolotl_types::Value) -> Routed {
        Routed {
            model_id: self.models[idx].id.clone(),
            output,
        }
    }

    #[cfg(not(test))]
    fn routed(&self, _idx: usize, output: xolotl_types::Value) -> Routed {
        Routed { output }
    }

    /// The single-backend offline baseline.
    #[cfg(any(
        test,
        not(any(
            feature = "openai-responses",
            feature = "openai-chat",
            feature = "anthropic-messages",
            feature = "gemini-generate-content"
        ))
    ))]
    pub(crate) fn baseline() -> Self {
        Self::new(vec![ModelEntry::new(
            "baseline/echo",
            Arc::new(crate::inference::EchoBackend),
        )])
    }

    /// Register an additional group (e.g. a fallback or modality-specific group).
    #[cfg(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn add_group(&mut self, group: ModelGroup) {
        self.groups.insert(group.name.clone(), group);
    }

    /// Set the group used when a request does not name one.
    #[cfg(any(
        test,
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn set_default_group(&mut self, name: impl Into<String>) {
        self.default_group = name.into();
    }

    /// Set the per-model retry count for retryable backend errors.
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
    pub(crate) fn set_max_retries(&mut self, n: u32) {
        self.max_retries = n;
    }

    /// Route an `infer` call: pick a group, filter by requirements, pick
    /// a model by policy, call with retry, and on whole-group failure escalate to
    /// the fallback group. `requirements` gates which models are candidates.
    pub(crate) async fn infer(
        &self,
        input: &xolotl_types::Value,
        requirements: &RequestRequirements,
        group: Option<&str>,
    ) -> Result<Routed, String> {
        let start = group.unwrap_or(&self.default_group).to_string();
        self.route(
            &start,
            input,
            requirements,
            RouteMethod::Infer,
            &mut Vec::new(),
        )
        .await
    }

    /// Route a `plan` call.
    pub(crate) async fn plan(
        &self,
        input: &xolotl_types::Value,
        requirements: &RequestRequirements,
        group: Option<&str>,
    ) -> Result<Routed, String> {
        let start = group.unwrap_or(&self.default_group).to_string();
        self.route(
            &start,
            input,
            requirements,
            RouteMethod::Plan,
            &mut Vec::new(),
        )
        .await
    }

    /// Embed routes the same way but calls `embed` on the chosen model.
    pub(crate) async fn embed(
        &self,
        input: &xolotl_types::Value,
        requirements: &RequestRequirements,
    ) -> Result<Routed, String> {
        // Embedding has no group escalation subtlety in the baseline: pick from
        // the default group's candidates and call embed with retry.
        let candidates = self.candidates(&self.default_group, requirements, RouteMethod::Embed);
        if candidates.is_empty() {
            return Err("no model satisfies the embed request's modality".into());
        }
        let mut last_err = String::new();
        for &idx in &candidates {
            match self.call_embed(idx, input).await {
                Ok(v) => {
                    return Ok(self.routed(idx, v));
                }
                Err(e) => last_err = e,
            }
        }
        Err(format!("all embed candidates failed: {last_err}"))
    }

    /// Rerank routes the same way but calls `rerank` on the chosen model.
    pub(crate) async fn rerank(
        &self,
        input: &xolotl_types::Value,
        requirements: &RequestRequirements,
    ) -> Result<Routed, String> {
        let candidates = self.candidates(&self.default_group, requirements, RouteMethod::Rerank);
        if candidates.is_empty() {
            return Err("no model satisfies the rerank request".into());
        }
        let mut last_err = String::new();
        for &idx in &candidates {
            match self.call_rerank(idx, input).await {
                Ok(v) => {
                    return Ok(self.routed(idx, v));
                }
                Err(e) => last_err = e,
            }
        }
        Err(format!("all rerank candidates failed: {last_err}"))
    }

    fn route<'a>(
        &'a self,
        group_name: &'a str,
        input: &'a xolotl_types::Value,
        requirements: &'a RequestRequirements,
        method: RouteMethod,
        visited: &'a mut Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Routed, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if visited.iter().any(|g| g == group_name) {
                return Err(format!("routing cycle through group '{group_name}'"));
            }
            visited.push(group_name.to_string());

            let candidates = self.candidates(group_name, requirements, method);
            // Try each candidate (ordered by the group policy) with per-model
            // retry; if the whole group fails, escalate to its fallback.
            let mut last_err = format!("no model in group '{group_name}' satisfies the request");
            for idx in self.order_candidates(group_name, &candidates) {
                match self.call_text_with_retry(idx, input, method).await {
                    Ok(v) => {
                        return Ok(self.routed(idx, v));
                    }
                    Err(e) => last_err = e,
                }
            }
            // Whole group failed → fallback.
            if let Some(group) = self.groups.get(group_name)
                && let Some(fallback) = &group.fallback
            {
                return self
                    .route(fallback, input, requirements, method, visited)
                    .await;
            }
            Err(last_err)
        })
    }

    /// The members of `group` whose capabilities satisfy `requirements`.
    fn candidates(
        &self,
        group: &str,
        req: &RequestRequirements,
        method: RouteMethod,
    ) -> Vec<usize> {
        let Some(g) = self.groups.get(group) else {
            return Vec::new();
        };
        g.members
            .iter()
            .copied()
            .filter(|&i| {
                let caps = self.models[i].caps;
                let method_ok = match method {
                    RouteMethod::Infer => caps.methods.infer,
                    RouteMethod::Embed => caps.methods.embed,
                    RouteMethod::Rerank => caps.methods.rerank,
                    RouteMethod::Plan => caps.methods.plan,
                };
                method_ok && caps.satisfies(req)
            })
            .collect()
    }

    /// Order candidates by the group's policy.
    fn order_candidates(&self, group: &str, candidates: &[usize]) -> Vec<usize> {
        let Some(g) = self.groups.get(group) else {
            return candidates.to_vec();
        };
        match g.policy {
            GroupPolicy::Priority => candidates.to_vec(),
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            GroupPolicy::RoundRobin => {
                let mut ordered = candidates.to_vec();
                let len = ordered.len();
                if len > 0 {
                    let n = g.rr_cursor.fetch_add(1, Ordering::Relaxed) as usize;
                    ordered.rotate_left(n % len);
                }
                ordered
            }
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            GroupPolicy::Latency => {
                let mut ordered = candidates.to_vec();
                ordered.sort_by_key(|&i| self.models[i].avg_latency_micros());
                ordered
            }
            #[cfg(any(
                feature = "openai-responses",
                feature = "openai-chat",
                feature = "anthropic-messages",
                feature = "gemini-generate-content"
            ))]
            GroupPolicy::Weighted => self.weighted_order(candidates),
        }
    }

    /// Deterministic weighted ordering: repeatedly pick by weight without
    /// replacement (xorshift RNG, seeded per Router → reproducible).
    #[cfg(any(
        feature = "openai-responses",
        feature = "openai-chat",
        feature = "anthropic-messages",
        feature = "gemini-generate-content"
    ))]
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

    async fn call_text_with_retry(
        &self,
        idx: usize,
        input: &xolotl_types::Value,
        method: RouteMethod,
    ) -> Result<xolotl_types::Value, String> {
        let model = &self.models[idx];
        let mut last_err = String::new();
        for attempt in 0..=self.max_retries {
            let t0 = std::time::Instant::now();
            let result = match method {
                RouteMethod::Infer => model.backend.infer(input).await,
                RouteMethod::Plan => model.backend.plan(input).await,
                RouteMethod::Embed | RouteMethod::Rerank => {
                    return Err("route method is not text inference".into());
                }
            };
            match result {
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
        input: &xolotl_types::Value,
    ) -> Result<xolotl_types::Value, String> {
        let model = &self.models[idx];
        let t0 = std::time::Instant::now();
        let r = model.backend.embed(input).await;
        model.record(t0.elapsed().as_micros() as u64, r.is_ok());
        r
    }

    async fn call_rerank(
        &self,
        idx: usize,
        input: &xolotl_types::Value,
    ) -> Result<xolotl_types::Value, String> {
        let model = &self.models[idx];
        let t0 = std::time::Instant::now();
        let r = model.backend.rerank(input).await;
        model.record(t0.elapsed().as_micros() as u64, r.is_ok());
        r
    }
}

/// Whether a backend error is transient and worth retrying.
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
    use anyhow::ensure;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicU32;
    use xolotl_types::Value;

    struct CountingBackend {
        label: &'static str,
        calls: Arc<AtomicU32>,
        fail_with: Option<String>,
        caps: ModelCapabilities,
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

        fn capabilities(&self) -> ModelCapabilities {
            self.caps
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
                caps: ModelCapabilities::default(),
            }),
        )
    }

    fn model_with_caps(
        id: &str,
        label: &'static str,
        calls: Arc<AtomicU32>,
        caps: ModelCapabilities,
    ) -> ModelEntry {
        ModelEntry::new(
            id,
            Arc::new(CountingBackend {
                label,
                calls,
                fail_with: None,
                caps,
            }),
        )
    }

    #[tokio::test]
    async fn priority_picks_first_healthy() -> anyhow::Result<()> {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            model("p/a", "a", c0.clone(), None),
            model("p/b", "b", c1.clone(), None),
        ]);
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .map_err(|error| anyhow::anyhow!("route inference: {error}"))?;
        ensure!(out.model_id == "p/a", "model id: {}", out.model_id);
        ensure!(c0.load(Ordering::SeqCst) == 1, "first model call count");
        ensure!(
            c1.load(Ordering::SeqCst) == 0,
            "second model not consulted when first succeeds"
        );
        Ok(())
    }

    #[tokio::test]
    async fn retries_then_falls_through_to_next_model() -> anyhow::Result<()> {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            model("p/a", "a", c0.clone(), Some("HTTP 503 unavailable")),
            model("p/b", "b", c1.clone(), None),
        ]);
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .map_err(|error| anyhow::anyhow!("route inference with retry: {error}"))?;
        ensure!(out.model_id == "p/b", "falls through to the healthy model");
        ensure!(
            c0.load(Ordering::SeqCst) == 3,
            "retried 429/5xx: 1 + 2 retries"
        );
        Ok(())
    }

    #[tokio::test]
    async fn permanent_error_is_not_retried() -> anyhow::Result<()> {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![
            model("p/a", "a", c0.clone(), Some("invalid api key")),
            model("p/b", "b", c1.clone(), None),
        ]);
        let routed = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .map_err(|error| anyhow::anyhow!("route inference with permanent error: {error}"))?;
        ensure!(routed.model_id == "p/b", "permanent error falls through");
        ensure!(
            c0.load(Ordering::SeqCst) == 1,
            "permanent error fails fast, no retry"
        );
        Ok(())
    }

    #[tokio::test]
    async fn fallback_group_on_whole_group_failure() -> anyhow::Result<()> {
        let c0 = Arc::new(AtomicU32::new(0));
        let c1 = Arc::new(AtomicU32::new(0));
        let mut r = Router::new(vec![
            model("primary/a", "a", c0.clone(), Some("invalid request")),
            model("backup/b", "b", c1.clone(), None),
        ]);
        r.add_group(
            ModelGroup::new("primary", GroupPolicy::Priority, vec![0]).with_fallback("backup"),
        );
        r.add_group(ModelGroup::new("backup", GroupPolicy::Priority, vec![1]));
        r.set_default_group("primary");
        let out = r
            .infer(&Value::Null, &RequestRequirements::default(), None)
            .await
            .map_err(|error| anyhow::anyhow!("route inference through fallback group: {error}"))?;
        ensure!(
            out.model_id == "backup/b",
            "escalated to fallback group: {}",
            out.model_id
        );
        Ok(())
    }

    #[tokio::test]
    async fn modality_filter_excludes_incapable_models() -> anyhow::Result<()> {
        let c0 = Arc::new(AtomicU32::new(0));
        let r = Router::new(vec![model("p/text", "t", c0, None)]);
        let req = RequestRequirements {
            needs_vision: true,
            ..Default::default()
        };
        ensure!(
            r.infer(&Value::Null, &req, None).await.is_err(),
            "vision request should exclude text-only model"
        );
        Ok(())
    }

    #[tokio::test]
    async fn method_filter_excludes_chat_only_from_embed() -> anyhow::Result<()> {
        let calls = Arc::new(AtomicU32::new(0));
        let caps = ModelCapabilities {
            methods: crate::inference::InferenceMethodSupport {
                infer: true,
                embed: false,
                rerank: false,
                plan: true,
            },
            ..Default::default()
        };
        let r = Router::new(vec![model_with_caps("p/chat", "chat", calls, caps)]);
        ensure!(
            r.embed(&Value::Null, &RequestRequirements::default())
                .await
                .is_err(),
            "embed request should exclude chat-only model"
        );
        Ok(())
    }
}
