#![forbid(unsafe_code)]

//! `xolotl-sim` — deterministic simulation harness for tests and replay.
//!
//! - [`ScriptedDriver`]: a programmable [`Driver`] whose responses are queued
//!   in advance, for testing programs without real effects.
//! - [`FixedClock`]: a `Driver` for `effect://time/*` pinned at a fixed
//!   timestamp, so `now` is reproducible.
//! - [`SimClock`]: an **advanceable** virtual clock for `effect://time/*`;
//!   `now`/`sleep` are served from a shared counter a test can `advance`/`set`,
//!   so time-dependent control flow is deterministic.
//! - [`CrashAfter`]: wraps any [`Driver`] and fails the (N+1)-th call to
//!   simulate "crash after the Nth Operation".
//! - [`why_not`]: a pure Fact projection explaining why an Operation
//!   ended denied / rejected — the "why-not" debug face.
//! - [`replay_report`]: classify a Process's recorded Facts the way recovery
//!   would, to assert determinism / pending handling.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use xolotl_kernel::{Bootstrap, Driver, DriverContext, DriverError, DynDriver, FactSink};
use xolotl_types::{MethodId, Outcome, OutputMode, ProcessId, Value};

/// A driver whose responses are queued in advance. Each call dequeues the next
/// scripted outcome; an empty queue yields `Failure::Cancelled`. Records every
/// input it received for assertions.
pub struct ScriptedDriver {
    /// Human-readable label for test diagnostics.
    pub label: String,
    queue: Mutex<VecDeque<Outcome>>,
    calls: Mutex<Vec<Value>>,
}

impl ScriptedDriver {
    /// Create an empty scripted driver with a diagnostic `label`.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            queue: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Queue a complete outcome for the next driver call.
    pub fn enqueue(&self, o: Outcome) {
        self.queue.lock().push_back(o);
    }

    /// Queue a successful [`Outcome::Done`] for the next driver call.
    pub fn enqueue_done<V: Into<Value>>(&self, v: V) {
        self.queue.lock().push_back(Outcome::Done(v.into()));
    }

    /// Return all input values received so far.
    pub fn calls(&self) -> Vec<Value> {
        self.calls.lock().clone()
    }
}

#[async_trait]
impl Driver for ScriptedDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        self.calls.lock().push(input);
        Ok(self
            .queue
            .lock()
            .pop_front()
            .unwrap_or(Outcome::Fail(xolotl_types::Failure::Cancelled)))
    }
}

/// A `Driver` for `effect://time/*` pinned at `t_millis` — deterministic `now`.
pub struct FixedClock {
    /// Fixed millisecond timestamp returned by every call.
    pub t_millis: i64,
}

#[async_trait]
impl Driver for FixedClock {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            0 => Ok(Outcome::Done(Value::Int(self.t_millis))),
            1 => {
                sim_sleep_millis(input)?;
                Ok(Outcome::Done(Value::Null))
            }
            2 => {
                let Value::Map(map) = input else {
                    return Err(DriverError::InvalidInput(
                        "time.cron requires object input".into(),
                    ));
                };
                let interval_ms = sim_cron_interval_ms(&map)?.ok_or_else(|| {
                    DriverError::InvalidInput(
                        "cron requires `interval_ms` or `every`/`unit`".into(),
                    )
                })?;
                let mut out = BTreeMap::new();
                out.insert(
                    "next_millis".into(),
                    Value::Int(self.t_millis.saturating_add(interval_ms)),
                );
                out.insert("interval_ms".into(), Value::Int(interval_ms));
                Ok(Outcome::Done(Value::Map(out)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

/// An **advanceable** virtual clock for `effect://time/*`. Unlike
/// [`FixedClock`], a test can move time forward with [`advance`](Self::advance)
/// or pin it with [`set`](Self::set); `now` reads the shared counter and
/// `sleep` advances it by the requested delay (no real waiting), so
/// time-dependent control flow runs deterministically and instantly.
///
/// Method ids follow the standard `effect://time` registration order. The
/// clock is `Clone` (shares one counter) so the test and the registered driver
/// observe the same time.
#[derive(Clone)]
pub struct SimClock {
    millis: Arc<AtomicI64>,
}

impl SimClock {
    /// Create a clock starting at `start_millis`.
    pub fn new(start_millis: i64) -> Self {
        Self {
            millis: Arc::new(AtomicI64::new(start_millis)),
        }
    }

    /// Current virtual time (millis since epoch).
    pub fn now(&self) -> i64 {
        self.millis.load(Ordering::SeqCst)
    }

    /// Advance virtual time by `delta_millis` (saturating at `i64::MAX`).
    /// Returns the new `now`.
    pub fn advance(&self, delta_millis: i64) -> i64 {
        // `fetch_add` returns the previous value; report the post-add time.
        let prev = self.millis.fetch_add(delta_millis.max(0), Ordering::SeqCst);
        prev.saturating_add(delta_millis.max(0))
    }

    /// Pin virtual time to an absolute `millis`.
    pub fn set(&self, millis: i64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new(0)
    }
}

#[async_trait]
impl Driver for SimClock {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            0 => Ok(Outcome::Done(Value::Int(self.now()))),
            1 => {
                let ms = sim_sleep_millis(input)?;
                self.advance(ms);
                Ok(Outcome::Done(Value::Null))
            }
            2 => {
                let Value::Map(map) = input else {
                    return Err(DriverError::InvalidInput(
                        "time.cron requires object input".into(),
                    ));
                };
                let interval_ms = sim_cron_interval_ms(&map)?.ok_or_else(|| {
                    DriverError::InvalidInput(
                        "cron requires `interval_ms` or `every`/`unit`".into(),
                    )
                })?;
                let mut out = BTreeMap::new();
                out.insert(
                    "next_millis".into(),
                    Value::Int(self.now().saturating_add(interval_ms)),
                );
                out.insert("interval_ms".into(), Value::Int(interval_ms));
                Ok(Outcome::Done(Value::Map(out)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn sim_sleep_millis(input: Value) -> Result<i64, DriverError> {
    let millis = match input {
        Value::Int(value) => value,
        Value::Map(map) => match map.get("millis") {
            Some(Value::Int(value)) => *value,
            Some(_) => {
                return Err(DriverError::InvalidInput(
                    "time.sleep millis must be an integer".into(),
                ));
            }
            None => {
                return Err(DriverError::InvalidInput(
                    "time.sleep requires `millis`".into(),
                ));
            }
        },
        _ => {
            return Err(DriverError::InvalidInput(
                "time.sleep requires integer input or `{millis}`".into(),
            ));
        }
    };
    if millis < 0 {
        return Err(DriverError::InvalidInput(
            "time.sleep millis must be nonnegative".into(),
        ));
    }
    Ok(millis)
}

fn sim_cron_interval_ms(m: &BTreeMap<String, Value>) -> Result<Option<i64>, DriverError> {
    if let Some(value) = m.get("interval_ms") {
        return match value {
            Value::Int(ms) => Ok((*ms > 0).then_some(*ms)),
            _ => Err(DriverError::InvalidInput(
                "time.cron interval_ms must be an integer".into(),
            )),
        };
    }
    let every = match m.get("every") {
        Some(Value::Int(value)) => *value,
        Some(_) => {
            return Err(DriverError::InvalidInput(
                "time.cron every must be an integer".into(),
            ));
        }
        None => return Ok(None),
    };
    if every <= 0 {
        return Ok(None);
    }
    let unit = match m.get("unit") {
        Some(Value::Str(unit)) => unit.as_str(),
        Some(_) => {
            return Err(DriverError::InvalidInput(
                "time.cron unit must be a string".into(),
            ));
        }
        None => "s",
    };
    let unit_ms = match unit {
        "s" | "sec" | "second" | "seconds" => 1000,
        "m" | "min" | "minute" | "minutes" => 60_000,
        "h" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return Ok(None),
    };
    every
        .checked_mul(unit_ms)
        .map(Some)
        .ok_or_else(|| DriverError::InvalidInput("time.cron interval overflowed i64".into()))
}

/// Wraps any [`Driver`] and injects a crash after a fixed number of successful
/// calls. The first `n` calls
/// delegate to the inner driver; the (n+1)-th and every later call return a
/// distinctive `DriverError` — the failure a Driver would surface when its
/// process dies mid-effect — so a test can assert the program halts at the Nth
/// Operation and exercise crash-recovery.
pub struct CrashAfter {
    inner: DynDriver,
    n: u64,
    seen: AtomicU64,
}

impl CrashAfter {
    /// Crash after `n` successful inner calls.
    pub fn new(inner: DynDriver, n: u64) -> Self {
        Self {
            inner,
            n,
            seen: AtomicU64::new(0),
        }
    }

    /// Wrap in an `Arc` for registration.
    pub fn arc(inner: DynDriver, n: u64) -> Arc<Self> {
        Arc::new(Self::new(inner, n))
    }

    /// How many calls have been delegated so far (excludes the crashed call).
    pub fn calls_made(&self) -> u64 {
        self.seen.load(Ordering::SeqCst).min(self.n)
    }

    /// Whether the crash point has been reached.
    pub fn has_crashed(&self) -> bool {
        self.seen.load(Ordering::SeqCst) > self.n
    }
}

#[async_trait]
impl Driver for CrashAfter {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        // `fetch_add` returns the prior count; this call is the (prior+1)-th.
        let nth = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
        if nth > self.n {
            return Err(DriverError::Transport(format!(
                "simulated crash: driver died after {} operation(s)",
                self.n
            )));
        }
        self.inner.call(method, input, output, ctx).await
    }
}

/// A simulation kernel: an in-memory [`Bootstrap`] plus convenience for
/// registering scripted effects.
pub struct Sim {
    /// In-memory kernel bootstrap used by the simulation.
    pub boot: Bootstrap,
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
    /// Create a simulation backed by [`Bootstrap::in_memory`].
    pub fn new() -> Self {
        Self {
            boot: Bootstrap::in_memory(),
        }
    }

    /// Register a single-method scripted effect; returns the resource name
    /// (open + bind it on an executor to run).
    pub fn scripted_effect(
        &self,
        path: &str,
        driver: Arc<ScriptedDriver>,
    ) -> Result<xolotl_types::ResourceName, xolotl_kernel::BootstrapError> {
        self.boot.register_effect(
            path,
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::Purity::Effectful,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            driver,
        )
    }
}

/// Replay classification of a Process's recorded facts. Mirrors what
/// recovery would decide; useful to assert determinism in tests.
pub fn replay_report(
    facts: &FactSink,
    process: ProcessId,
) -> Result<xolotl_kernel::RecoveryReport, xolotl_kernel::FactError> {
    xolotl_kernel::recover_process(facts, process).map(|(report, _, _)| report)
}

/// The "why-not" explanation for one Operation. A pure projection over the
/// Process's Facts — it reads the recorded `decision`, `taint`, and
/// outcome, and never re-runs anything. Answers: did the Operation reach a
/// decision, what was it, was its input tainted / protected, and a
/// human-readable summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhyNot {
    /// The Operation being explained.
    pub op: xolotl_types::OperationId,
    /// The recorded decision tag (the proximate verdict).
    pub decision: xolotl_types::DecisionTag,
    /// Whether the input lineage touched a protected source — the
    /// structural reason an outbound Operation is denied.
    pub tainted_protected: bool,
    /// Whether the input lineage touched untrusted content (model / inbound /
    /// fetched) — the memory-poison / injection signal.
    pub tainted_untrusted: bool,
    /// Human-readable explanation.
    pub explanation: String,
}

impl WhyNot {
    /// Whether the Operation was allowed (`DecisionTag::Ok`).
    pub fn was_allowed(&self) -> bool {
        self.decision.is_ok()
    }
}

/// Explain why Operation `op` ended the way it did, from a Process's recorded
/// Facts.
///
/// Returns `None` if no Fact for `op` exists (the Operation never reached a
/// decision — e.g. its graph cursor was never reached). Otherwise returns a
/// [`WhyNot`] describing the decision and the taint lineage that drove it. This
/// is deliberately a *pure* read over Facts: the same defense lineage
/// (`Fact.taint`, `Fact.decision`) the data plane recorded at decision time.
pub fn why_not(facts: &[xolotl_types::Fact], op: xolotl_types::OperationId) -> Option<WhyNot> {
    use xolotl_types::DecisionTag;
    // Latest attempt wins if several Facts share the position (retries).
    let fact = facts
        .iter()
        .filter(|f| f.id.process == op.process && f.id.position == op.position)
        .max_by_key(|f| f.id.attempt)?;

    let tainted_protected = fact.taint.has_protected();
    let tainted_untrusted = fact.taint.has_untrusted_content();

    let verdict = match fact.decision {
        DecisionTag::Ok => "the operation was allowed and completed".to_string(),
        DecisionTag::Denied => {
            "denied by a capability / owner / rights check (the caller lacked the \
             authority to perform it)"
                .to_string()
        }
        DecisionTag::RejectedByPolicy => {
            let mut s = "rejected by a residual policy check".to_string();
            if tainted_protected {
                s.push_str(
                    "; its input lineage touched a protected source, so an \
                            outbound flow is structurally denied",
                );
            } else if tainted_untrusted {
                s.push_str("; its input carried untrusted content (model/inbound/fetched)");
            }
            s
        }
        DecisionTag::DriverError => "the driver returned an error".to_string(),
        DecisionTag::Timeout => "the operation timed out".to_string(),
        DecisionTag::Cancelled => "the operation was cancelled".to_string(),
        DecisionTag::Quarantined => {
            "held in quarantine as an unsafe replay, pending an operator decision".to_string()
        }
    };

    let explanation = format!("operation {op}: {verdict}");
    Some(WhyNot {
        op,
        decision: fact.decision,
        tainted_protected,
        tainted_untrusted,
        explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use xolotl_graph::{ActorSpec, DoNode, OperationTemplate, StepRef};
    use xolotl_kernel::ProcessStepBinding;
    use xolotl_types::OutputMode;

    fn run_prog(name: xolotl_types::ResourceName) -> DoNode {
        run_prog_with(name, Value::Null)
    }

    fn run_prog_with(name: xolotl_types::ResourceName, input: Value) -> DoNode {
        DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        })
    }

    async fn wait_actor_status(
        boot: &Bootstrap,
        directory: &xolotl_types::Path,
        status: &str,
    ) -> anyhow::Result<Value> {
        for _ in 0..100 {
            if let Some(value) = boot.kernel.state.read(directory).await?
                && value
                    .as_map()
                    .and_then(|map| map.get("status"))
                    .and_then(Value::as_str)
                    == Some(status)
            {
                return Ok(value);
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        bail!("actor directory did not reach status {status}");
    }

    fn is_process_finalized_fact(fact: &xolotl_types::Fact) -> bool {
        matches!(
            &fact.outcome_ref,
            xolotl_types::OutcomeRef::Inline(Value::Map(map))
                if map.get("event").and_then(Value::as_str) == Some("ProcessFinalized")
        )
    }

    #[tokio::test]
    async fn scripted_driver_returns_queued_outcomes() -> anyhow::Result<()> {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("model"));
        driver.enqueue_done(Value::Str("first".into()));
        let name = sim.scripted_effect("effect://model/x", driver.clone())?;
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform")?;
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        let out = ex.eval(&run_prog(name)).await;
        ensure!(
            out == Outcome::Done(Value::Str("first".into())),
            "unexpected scripted outcome: {out:?}"
        );
        ensure!(driver.calls().len() == 1, "unexpected call count");
        Ok(())
    }

    #[tokio::test]
    async fn injected_failure_routes_through_or_else_recovery_step() -> anyhow::Result<()> {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("primary"));
        driver.enqueue(Outcome::Fail(xolotl_types::Failure::Cancelled));
        let name = sim.scripted_effect("effect://primary/fallible", driver.clone())?;
        let spec = ActorSpec {
            name: "fallible-recovery".into(),
            body: run_prog(name).or_else(StepRef::new(sim.boot.root, "fallback")),
            declared_capabilities: vec!["perform://effect/primary/fallible".into()],
            ..ActorSpec::default()
        };
        let actor = sim
            .boot
            .spawn_actor_under_with_steps(
                sim.boot.root,
                xolotl_types::IdentityRef::ROOT,
                "root",
                &spec,
                [ProcessStepBinding::new(
                    "fallback",
                    Arc::new(|v, _| match v {
                        Value::Str(reason) if reason.contains("cancelled") => {
                            DoNode::pure(Value::Str("fallback".into()))
                        }
                        other => DoNode::pure(Value::Str(format!(
                            "unexpected recovery input: {other:?}"
                        ))),
                    }),
                )],
            )
            .await?;
        let value = wait_actor_status(&sim.boot, &actor.directory, "completed").await?;
        ensure!(
            value
                .as_map()
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("completed"),
            "unexpected actor directory entry: {value:?}"
        );
        ensure!(driver.calls().len() == 1, "unexpected call count");
        let facts = sim.boot.kernel.facts.facts_of(actor.process)?;
        let operation_facts = facts
            .iter()
            .filter(|fact| !is_process_finalized_fact(fact))
            .collect::<Vec<_>>();
        ensure!(
            operation_facts.len() == 1,
            "unexpected operation fact count: {}",
            operation_facts.len()
        );
        let fact = operation_facts
            .first()
            .copied()
            .context("missing operation fact")?;
        ensure!(
            fact.decision == xolotl_types::DecisionTag::DriverError,
            "unexpected decision: {:?}",
            fact.decision
        );
        Ok(())
    }

    #[tokio::test]
    async fn replay_report_counts_recorded_facts() -> anyhow::Result<()> {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("m"));
        driver.enqueue_done(Value::Int(1));
        let name = sim.scripted_effect("effect://m/x", driver)?;
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform")?;
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        ex.eval(&run_prog(name)).await;
        let report = replay_report(&sim.boot.kernel.facts, sim.boot.root)?;
        ensure!(
            report.skipped == 1,
            "one completed effect should be skipped on replay"
        );
        Ok(())
    }

    #[tokio::test]
    async fn budget_denial_records_fact_without_calling_scripted_driver() -> anyhow::Result<()> {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("costly"));
        driver.enqueue_done(Value::Int(99));
        let name = sim.boot.register_effect_with_cost(
            "effect://costly/call",
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::Purity::Effectful,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            driver.clone(),
            xolotl_types::CostModel {
                flat_micro_usd: 1_000,
                ..Default::default()
            },
        )?;
        ensure!(
            sim.boot.kernel.processes.set_budget_spec(
                sim.boot.root,
                xolotl_types::BudgetSpec {
                    daily_micro_usd: Some(999),
                    ..Default::default()
                },
            ),
            "root process missing while setting test budget"
        );
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform")?;
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);

        let out = ex
            .eval(&run_prog_with(name, Value::Str("pay".into())))
            .await;

        match out {
            Outcome::Fail(xolotl_types::Failure::BudgetExhausted { dim }) => {
                ensure!(
                    dim == "daily_micro_usd",
                    "unexpected budget dimension: {dim}"
                );
            }
            other => bail!("expected budget denial, got {other:?}"),
        }
        ensure!(
            driver.calls().is_empty(),
            "budget denial must happen before the scripted driver is invoked"
        );
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root)?;
        ensure!(facts.len() == 1, "unexpected fact count: {}", facts.len());
        ensure!(
            facts[0].decision == xolotl_types::DecisionTag::RejectedByPolicy,
            "unexpected decision: {:?}",
            facts[0].decision
        );
        ensure!(facts[0].handle == handle, "unexpected fact handle");
        ensure!(
            facts[0].resource != xolotl_types::ResourceId::new(0),
            "fact resource should be assigned"
        );
        ensure!(
            facts[0].replay == xolotl_types::ReplayClass::NonIdempotentEffect,
            "unexpected replay class: {:?}",
            facts[0].replay
        );
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_duplicate_short_circuits_driver_and_records_attempt() -> anyhow::Result<()>
    {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("idempotent"));
        driver.enqueue_done(Value::Str("created".into()));
        let name = sim.boot.register_effect(
            "effect://orders/create",
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::Purity::Idempotent,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            driver.clone(),
        )?;
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform")?;
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        let mut input = std::collections::BTreeMap::new();
        input.insert("_idem_key".into(), Value::Str("order-42".into()));
        let prog = run_prog_with(name, Value::Map(input));

        let first = ex.eval(&prog).await;
        let second = ex.eval(&prog).await;

        ensure!(
            first == Outcome::Done(Value::Str("created".into())),
            "unexpected first outcome: {first:?}"
        );
        ensure!(
            second == Outcome::Done(Value::Str("created".into())),
            "unexpected second outcome: {second:?}"
        );
        ensure!(
            driver.calls().len() == 1,
            "the replayed node must use the idempotency cache"
        );
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root)?;
        ensure!(facts.len() == 1, "same OperationId updates the same fact");
        ensure!(
            facts[0].decision == xolotl_types::DecisionTag::Ok,
            "unexpected decision: {:?}",
            facts[0].decision
        );
        ensure!(
            facts[0].replay == xolotl_types::ReplayClass::IdempotentEffect,
            "unexpected replay class: {:?}",
            facts[0].replay
        );
        Ok(())
    }

    #[tokio::test]
    async fn fixed_clock_matches_standard_time_method_shape() -> anyhow::Result<()> {
        let ctx = DriverContext::new(xolotl_types::IdentityRef::ROOT, ProcessId::new(1));
        let clock = FixedClock { t_millis: 10_000 };

        let now = clock
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            now == Outcome::Done(Value::Int(10_000)),
            "unexpected fixed now output: {now:?}"
        );

        let sleep = clock
            .call(MethodId::new(1), Value::Int(250), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            sleep == Outcome::Done(Value::Null),
            "unexpected fixed sleep output: {sleep:?}"
        );

        let cron = clock
            .call(
                MethodId::new(2),
                Value::Map(BTreeMap::from([("interval_ms".into(), Value::Int(500))])),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        match cron {
            Outcome::Done(Value::Map(map)) => {
                ensure!(
                    map.get("next_millis") == Some(&Value::Int(10_500)),
                    "unexpected fixed cron output: {map:?}"
                );
            }
            other => bail!("unexpected fixed cron outcome: {other:?}"),
        }

        ensure!(
            matches!(
                clock
                    .call(MethodId::new(99), Value::Null, OutputMode::Unary, &ctx)
                    .await,
                Err(DriverError::NoSuchMethod(method)) if method == MethodId::new(99)
            ),
            "unknown fixed clock method should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sim_clock_now_reflects_advance_and_set() -> anyhow::Result<()> {
        let ctx = DriverContext::new(xolotl_types::IdentityRef::ROOT, ProcessId::new(1));
        let clock = SimClock::new(1_000);
        let out = clock
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out == Outcome::Done(Value::Int(1_000)),
            "unexpected initial clock output: {out:?}"
        );

        ensure!(clock.advance(500) == 1_500, "unexpected advanced time");
        let out = clock
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out == Outcome::Done(Value::Int(1_500)),
            "unexpected advanced clock output: {out:?}"
        );

        let mut m = BTreeMap::new();
        m.insert("millis".into(), Value::Int(250));
        let out = clock
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out == Outcome::Done(Value::Null),
            "unexpected sleep output: {out:?}"
        );
        ensure!(clock.now() == 1_750, "unexpected time after sleep");

        let mut cron = BTreeMap::new();
        cron.insert("every".into(), Value::Int(2));
        cron.insert("unit".into(), Value::Str("s".into()));
        let out = clock
            .call(MethodId::new(2), Value::Map(cron), OutputMode::Unary, &ctx)
            .await?;
        match out {
            Outcome::Done(Value::Map(map)) => {
                ensure!(
                    map.get("interval_ms") == Some(&Value::Int(2_000)),
                    "unexpected cron interval: {map:?}"
                );
                ensure!(
                    map.get("next_millis") == Some(&Value::Int(3_750)),
                    "unexpected cron next time: {map:?}"
                );
            }
            other => bail!("unexpected cron output: {other:?}"),
        }

        clock.set(42);
        ensure!(clock.now() == 42, "unexpected set time");
        Ok(())
    }

    #[tokio::test]
    async fn sim_clock_rejects_malformed_time_calls() -> anyhow::Result<()> {
        let ctx = DriverContext::new(xolotl_types::IdentityRef::ROOT, ProcessId::new(1));
        let clock = SimClock::new(0);

        for input in [
            Value::Null,
            Value::Map(BTreeMap::new()),
            Value::Map(BTreeMap::from([("millis".into(), Value::Str("0".into()))])),
            Value::Int(-1),
        ] {
            let out = clock
                .call(MethodId::new(1), input, OutputMode::Unary, &ctx)
                .await;
            ensure!(out.is_err(), "malformed sleep input should fail closed");
        }

        let bad_unit = Value::Map(BTreeMap::from([
            ("every".into(), Value::Int(1)),
            ("unit".into(), Value::Str("fortnight".into())),
        ]));
        ensure!(
            clock
                .call(MethodId::new(2), bad_unit, OutputMode::Unary, &ctx)
                .await
                .is_err(),
            "malformed cron input should fail closed"
        );
        ensure!(
            matches!(
                clock
                    .call(MethodId::new(99), Value::Null, OutputMode::Unary, &ctx)
                    .await,
                Err(DriverError::NoSuchMethod(method)) if method == MethodId::new(99)
            ),
            "unknown time method should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn crash_after_n_stops_at_the_nth_call() -> anyhow::Result<()> {
        let ctx = DriverContext::new(xolotl_types::IdentityRef::ROOT, ProcessId::new(1));
        let crasher = CrashAfter::arc(Arc::new(xolotl_kernel::EchoDriver), 2);
        let a = crasher
            .call(MethodId::new(0), Value::Int(1), OutputMode::Unary, &ctx)
            .await;
        let b = crasher
            .call(MethodId::new(0), Value::Int(2), OutputMode::Unary, &ctx)
            .await;
        ensure!(
            a? == Outcome::Done(Value::Int(1)),
            "unexpected first delegated output"
        );
        ensure!(
            b? == Outcome::Done(Value::Int(2)),
            "unexpected second delegated output"
        );
        ensure!(!crasher.has_crashed(), "driver should not have crashed yet");
        ensure!(crasher.calls_made() == 2, "unexpected call count");

        let c = crasher
            .call(MethodId::new(0), Value::Int(3), OutputMode::Unary, &ctx)
            .await;
        ensure!(
            matches!(c, Err(DriverError::Transport(_))),
            "Nth+1 call crashes"
        );
        ensure!(crasher.has_crashed(), "driver should be crashed");
        let d = crasher
            .call(MethodId::new(0), Value::Int(4), OutputMode::Unary, &ctx)
            .await;
        ensure!(d.is_err(), "stays crashed after the crash point");
        Ok(())
    }

    #[test]
    fn why_not_explains_a_denied_fact() -> anyhow::Result<()> {
        use xolotl_types::ids::NodeId;
        use xolotl_types::{
            DecisionTag, Fact, HandleId, IdentityRef, MethodId, OperationId, OutcomeRef, Path,
            ProcessId, ReplayClass, ResourceId, TaintSet, TaintSource, Timestamp, ValueRef,
        };

        let op = OperationId::new(ProcessId::new(7), NodeId::new(3), 0);
        // A residual policy rejected an outbound op whose input touched the vault.
        let mut taint = TaintSet::of(TaintSource::ModelOutput);
        taint.add(TaintSource::Protected {
            path: Path::parse("state://vault/alice/x")?,
        });
        let fact = Fact {
            id: op,
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(7),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Str("post this".into())),
            taint,
            decision: DecisionTag::RejectedByPolicy,
            outcome_ref: OutcomeRef::None,
            batch: None,
            replay: ReplayClass::NonIdempotentEffect,
            timestamp: Timestamp::millis(1),
        };

        let why = why_not(&[fact], op).context("missing why-not explanation")?;
        ensure!(
            why.decision == DecisionTag::RejectedByPolicy,
            "unexpected decision: {:?}",
            why.decision
        );
        ensure!(!why.was_allowed(), "denied fact should not be allowed");
        ensure!(why.tainted_protected, "lineage touched a protected source");
        ensure!(why.tainted_untrusted, "lineage also carried model output");
        ensure!(
            why.explanation.contains("protected source"),
            "{}",
            why.explanation
        );

        // No Fact for an unrelated op ⇒ no explanation (cursor never reached it).
        let other = OperationId::new(ProcessId::new(7), NodeId::new(99), 0);
        ensure!(
            why_not(&[], other).is_none(),
            "unrelated op should have no explanation"
        );
        Ok(())
    }
}
