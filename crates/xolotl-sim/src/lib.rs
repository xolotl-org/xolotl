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
use xolotl_kernel::{
    Bootstrap, Driver, DriverContext, DriverError, DriverOutput, DynDriver, FactSink,
};
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
    ) -> Result<DriverOutput, DriverError> {
        self.calls.lock().push(input);
        Ok(DriverOutput::new(self.queue.lock().pop_front().unwrap_or(
            Outcome::Fail(xolotl_types::Failure::Cancelled),
        )))
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
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            0 => Ok(DriverOutput::new(Outcome::Done(Value::integer(
                self.t_millis,
            )))),
            1 => {
                sim_sleep_millis(input)?;
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            }
            2 => {
                let Some(map) = input.as_map() else {
                    return Err(DriverError::InvalidInput(
                        "time.cron requires object input".into(),
                    ));
                };
                let interval_ms = sim_cron_interval_ms(map)?.ok_or_else(|| {
                    DriverError::InvalidInput(
                        "cron requires `interval_ms` or `every`/`unit`".into(),
                    )
                })?;
                let mut out = BTreeMap::new();
                out.insert(
                    "next_millis".into(),
                    Value::integer(self.t_millis.saturating_add(interval_ms)),
                );
                out.insert("interval_ms".into(), Value::integer(interval_ms));
                Ok(DriverOutput::new(Outcome::Done(Value::map(out))))
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
        let delta = delta_millis.max(0);
        match self
            .millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |time| {
                Some(time.saturating_add(delta))
            }) {
            Ok(previous) => previous.saturating_add(delta),
            Err(current) => current,
        }
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
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            0 => Ok(DriverOutput::new(Outcome::Done(Value::integer(self.now())))),
            1 => {
                let ms = sim_sleep_millis(input)?;
                self.advance(ms);
                Ok(DriverOutput::new(Outcome::Done(Value::null())))
            }
            2 => {
                let Some(map) = input.as_map() else {
                    return Err(DriverError::InvalidInput(
                        "time.cron requires object input".into(),
                    ));
                };
                let interval_ms = sim_cron_interval_ms(map)?.ok_or_else(|| {
                    DriverError::InvalidInput(
                        "cron requires `interval_ms` or `every`/`unit`".into(),
                    )
                })?;
                let mut out = BTreeMap::new();
                out.insert(
                    "next_millis".into(),
                    Value::integer(self.now().saturating_add(interval_ms)),
                );
                out.insert("interval_ms".into(), Value::integer(interval_ms));
                Ok(DriverOutput::new(Outcome::Done(Value::map(out))))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn sim_sleep_millis(input: Value) -> Result<i64, DriverError> {
    let millis = match input.view() {
        xolotl_types::ValueView::Int(value) => value,
        xolotl_types::ValueView::Map(map) => match map.get("millis") {
            Some(value) => value.as_int().ok_or_else(|| {
                DriverError::InvalidInput("time.sleep millis must be an integer".into())
            })?,
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

fn sim_cron_interval_ms(m: &xolotl_types::ValueMap) -> Result<Option<i64>, DriverError> {
    if let Some(value) = m.get("interval_ms") {
        return match value.as_int() {
            Some(ms) => Ok((ms > 0).then_some(ms)),
            _ => Err(DriverError::InvalidInput(
                "time.cron interval_ms must be an integer".into(),
            )),
        };
    }
    let every = match m.get("every") {
        Some(value) => value.as_int().ok_or_else(|| {
            DriverError::InvalidInput("time.cron every must be an integer".into())
        })?,
        None => return Ok(None),
    };
    if every <= 0 {
        return Ok(None);
    }
    let unit = match m.get("unit") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| DriverError::InvalidInput("time.cron unit must be a string".into()))?,
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
    ) -> Result<DriverOutput, DriverError> {
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
    xolotl_kernel::recover_process(facts, process).map(|(report, _)| report)
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

/// Explain the latest explicit attempt of `op`'s invocation from recorded Facts.
///
/// Returns `None` if no Fact for `op` exists (the Operation never reached a
/// decision — e.g. its graph cursor was never reached). Otherwise returns a
/// [`WhyNot`] describing the decision and the taint lineage that drove it. This
/// is deliberately a *pure* read over Facts: the same defense lineage
/// (`Fact.taint`, `Fact.decision`) the data plane recorded at decision time.
pub fn why_not(facts: &[xolotl_types::Fact], op: xolotl_types::OperationId) -> Option<WhyNot> {
    use xolotl_types::DecisionTag;
    // Retries share one invocation; repeated call sites and executions do not.
    let fact = facts
        .iter()
        .filter(|f| {
            f.id.process == op.process
                && f.id.execution == op.execution
                && f.id.invocation == op.invocation
                && f.id.position == op.position
        })
        .max_by_key(|f| f.id.attempt)?;
    let op = fact.id;

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
    use xolotl_kernel::{StepBinding, StepModule};
    use xolotl_types::OutputMode;

    fn run_prog(name: xolotl_types::ResourceName) -> DoNode {
        run_prog_with(name, Value::null())
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
        fact.outcome
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|map| map.get("event"))
            .and_then(Value::as_str)
            == Some("ProcessFinalized")
    }

    #[tokio::test]
    async fn scripted_driver_returns_queued_outcomes() -> anyhow::Result<()> {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("model"));
        driver.enqueue_done(Value::string("first".into()));
        let name = sim.scripted_effect("effect://model/x", driver.clone())?;
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform")?;
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        let out = ex.eval(&run_prog(name)).await.outcome;
        ensure!(
            out == Outcome::Done(Value::string("first".into())),
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
            body: run_prog(name).or_else(StepRef::new("fallback")),
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
                StepModule::new([StepBinding::new(
                    "fallback",
                    Arc::new(|v, _| match v.view() {
                        xolotl_types::ValueView::Str(reason) if reason.contains("cancelled") => {
                            DoNode::pure(Value::string("fallback".into()))
                        }
                        other => DoNode::pure(Value::string(format!(
                            "unexpected recovery input: {other:?}"
                        ))),
                    }),
                )])?,
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
        driver.enqueue_done(Value::integer(1));
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
        driver.enqueue_done(Value::integer(99));
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
            .eval(&run_prog_with(name, Value::string("pay".into())))
            .await
            .outcome;

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
        driver.enqueue_done(Value::string("created".into()));
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
        input.insert("_idem_key".into(), Value::string("order-42".into()));
        let prog = run_prog_with(name, Value::map(input));

        let first = ex.eval(&prog).await.outcome;
        let second = ex.eval(&prog).await.outcome;

        ensure!(
            first == Outcome::Done(Value::string("created".into())),
            "unexpected first outcome: {first:?}"
        );
        ensure!(
            second == Outcome::Done(Value::string("created".into())),
            "unexpected second outcome: {second:?}"
        );
        ensure!(
            driver.calls().len() == 1,
            "the business key must use the idempotency cache"
        );
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root)?;
        ensure!(
            facts.len() == 2,
            "independent executions retain distinct facts"
        );
        ensure!(facts[0].id.execution != facts[1].id.execution);
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
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            now.outcome == Outcome::Done(Value::integer(10_000)),
            "unexpected fixed now output: {now:?}"
        );

        let sleep = clock
            .call(
                MethodId::new(1),
                Value::integer(250),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        ensure!(
            sleep.outcome == Outcome::Done(Value::null()),
            "unexpected fixed sleep output: {sleep:?}"
        );

        let cron = clock
            .call(
                MethodId::new(2),
                Value::map(BTreeMap::from([(
                    "interval_ms".into(),
                    Value::integer(500),
                )])),
                OutputMode::Unary,
                &ctx,
            )
            .await?;
        match cron.outcome {
            Outcome::Done(value) => {
                let map = value.as_map().context("expected object result")?;
                ensure!(
                    map.get("next_millis") == Some(&Value::integer(10_500)),
                    "unexpected fixed cron output: {map:?}"
                );
            }
            other => bail!("unexpected fixed cron outcome: {other:?}"),
        }

        ensure!(
            matches!(
                clock
                    .call(MethodId::new(99), Value::null(), OutputMode::Unary, &ctx)
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
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(1_000)),
            "unexpected initial clock output: {out:?}"
        );

        ensure!(clock.advance(500) == 1_500, "unexpected advanced time");
        let out = clock
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(1_500)),
            "unexpected advanced clock output: {out:?}"
        );

        let mut m = BTreeMap::new();
        m.insert("millis".into(), Value::integer(250));
        let out = clock
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx)
            .await?;
        ensure!(
            out.outcome == Outcome::Done(Value::null()),
            "unexpected sleep output: {out:?}"
        );
        ensure!(clock.now() == 1_750, "unexpected time after sleep");

        let mut cron = BTreeMap::new();
        cron.insert("every".into(), Value::integer(2));
        cron.insert("unit".into(), Value::string("s".into()));
        let out = clock
            .call(MethodId::new(2), Value::map(cron), OutputMode::Unary, &ctx)
            .await?;
        match out.outcome {
            Outcome::Done(value) => {
                let map = value.as_map().context("expected object result")?;
                ensure!(
                    map.get("interval_ms") == Some(&Value::integer(2_000)),
                    "unexpected cron interval: {map:?}"
                );
                ensure!(
                    map.get("next_millis") == Some(&Value::integer(3_750)),
                    "unexpected cron next time: {map:?}"
                );
            }
            other => bail!("unexpected cron output: {other:?}"),
        }

        clock.set(42);
        ensure!(clock.now() == 42, "unexpected set time");
        Ok(())
    }

    #[test]
    fn sim_clock_stores_saturated_time_without_wrapping() -> anyhow::Result<()> {
        let clock = SimClock::new(i64::MAX - 1);
        let shared = clock.clone();
        for delta in [2, i64::MAX, 1, 0, -1, i64::MIN] {
            ensure!(clock.advance(delta) == i64::MAX, "advance must saturate");
            ensure!(shared.now() == i64::MAX, "stored time must not wrap");
        }
        clock.set(i64::MIN);
        ensure!(
            clock.advance(-1) == i64::MIN,
            "negative deltas do not rewind"
        );
        ensure!(clock.advance(i64::MAX) == -1, "full-width addition");
        ensure!(shared.now() == -1, "shared clock observes the same time");
        Ok(())
    }

    #[tokio::test]
    async fn sim_clock_rejects_malformed_time_calls() -> anyhow::Result<()> {
        let ctx = DriverContext::new(xolotl_types::IdentityRef::ROOT, ProcessId::new(1));
        let clock = SimClock::new(0);

        for input in [
            Value::null(),
            Value::map(BTreeMap::new()),
            Value::map(BTreeMap::from([(
                "millis".into(),
                Value::string("0".into()),
            )])),
            Value::integer(-1),
        ] {
            let out = clock
                .call(MethodId::new(1), input, OutputMode::Unary, &ctx)
                .await;
            ensure!(out.is_err(), "malformed sleep input should fail closed");
        }

        let bad_unit = Value::map(BTreeMap::from([
            ("every".into(), Value::integer(1)),
            ("unit".into(), Value::string("fortnight".into())),
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
                    .call(MethodId::new(99), Value::null(), OutputMode::Unary, &ctx)
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
            .call(MethodId::new(0), Value::integer(1), OutputMode::Unary, &ctx)
            .await;
        let b = crasher
            .call(MethodId::new(0), Value::integer(2), OutputMode::Unary, &ctx)
            .await;
        ensure!(
            a?.outcome == Outcome::Done(Value::integer(1)),
            "unexpected first delegated output"
        );
        ensure!(
            b?.outcome == Outcome::Done(Value::integer(2)),
            "unexpected second delegated output"
        );
        ensure!(!crasher.has_crashed(), "driver should not have crashed yet");
        ensure!(crasher.calls_made() == 2, "unexpected call count");

        let c = crasher
            .call(MethodId::new(0), Value::integer(3), OutputMode::Unary, &ctx)
            .await;
        ensure!(
            matches!(c, Err(DriverError::Transport(_))),
            "Nth+1 call crashes"
        );
        ensure!(crasher.has_crashed(), "driver should be crashed");
        let d = crasher
            .call(MethodId::new(0), Value::integer(4), OutputMode::Unary, &ctx)
            .await;
        ensure!(d.is_err(), "stays crashed after the crash point");
        Ok(())
    }

    #[test]
    fn why_not_explains_a_denied_fact() -> anyhow::Result<()> {
        use xolotl_types::ids::NodeId;
        use xolotl_types::{
            DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId,
            OperationId, Path, ProcessId, ReplayClass, ResourceId, TaintSet, TaintSource,
            Timestamp,
        };

        let op = OperationId::new(
            ProcessId::new(7),
            ExecutionId::FIRST,
            InvocationId::new(4),
            NodeId::new(3),
            0,
        );
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
            input: Value::string("post this".into()),
            taint,
            decision: DecisionTag::RejectedByPolicy,
            outcome: None,
            batch: None,
            replay: ReplayClass::NonIdempotentEffect,
            timestamp: Timestamp::millis(1),
        };

        let mut retry = fact.clone();
        retry.id = op.retry().context("retry remains representable")?;
        let mut repeated = retry.clone();
        repeated.id.invocation = InvocationId::new(5);
        repeated.id.attempt = 2;
        repeated.decision = DecisionTag::Ok;
        let mut independent = repeated.clone();
        independent.id.invocation = op.invocation;
        independent.id.execution = ExecutionId::new(2).context("nonzero scope")?;
        let facts = [fact, retry.clone(), repeated, independent];
        let why = why_not(&facts, op).context("missing why-not explanation")?;
        ensure!(
            why.op == retry.id,
            "diagnostic should identify the selected attempt"
        );
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
        let other = OperationId {
            position: NodeId::new(99),
            ..op
        };
        ensure!(
            why_not(&facts, other).is_none(),
            "unrelated op should have no explanation"
        );
        Ok(())
    }
}
