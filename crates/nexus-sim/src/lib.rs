#![forbid(unsafe_code)]

//! `nexus-sim` — deterministic simulation harness for tests and replay (§23).
//!
//! - [`ScriptedDriver`]: a programmable [`Driver`] whose responses are queued
//!   in advance, for testing programs without real effects.
//! - [`FixedClock`]: a `Driver` for `effect://time/*` pinned at a fixed
//!   timestamp, so `now` is reproducible.
//! - [`SimClock`]: an **advanceable** virtual clock for `effect://time/*`;
//!   `now`/`sleep` are served from a shared counter a test can `advance`/`set`,
//!   so time-dependent control flow is deterministic (§23).
//! - [`CrashAfter`]: wraps any [`Driver`] and fails the (N+1)-th call to
//!   simulate "crash after the Nth Operation" (§23).
//! - [`why_not`]: a pure Fact projection (§9.1) explaining why an Operation
//!   ended denied / rejected — the "why-not" debug face (§23).
//! - [`replay_report`]: classify a Process's recorded Facts the way recovery
//!   would (§15), to assert determinism / pending handling.

use async_trait::async_trait;
use nexus_kernel::{Bootstrap, Driver, DriverContext, DriverError, DynDriver, FactSink};
use nexus_types::{MethodId, Outcome, OutputMode, ProcessId, Value};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A driver whose responses are queued in advance. Each call dequeues the next
/// scripted outcome; an empty queue yields `Failure::Cancelled`. Records every
/// input it received for assertions.
pub struct ScriptedDriver {
    pub label: String,
    queue: Mutex<VecDeque<Outcome>>,
    calls: Mutex<Vec<Value>>,
}

impl ScriptedDriver {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            queue: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn enqueue(&self, o: Outcome) {
        self.queue.lock().push_back(o);
    }

    pub fn enqueue_done<V: Into<Value>>(&self, v: V) {
        self.queue.lock().push_back(Outcome::Done(v.into()));
    }

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
            .unwrap_or(Outcome::Fail(nexus_types::Failure::Cancelled)))
    }
}

/// A `Driver` for `effect://time/*` pinned at `t_millis` — deterministic `now`.
pub struct FixedClock {
    pub t_millis: i64,
}

#[async_trait]
impl Driver for FixedClock {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        Ok(Outcome::Done(Value::Int(self.t_millis)))
    }
}

/// An **advanceable** virtual clock for `effect://time/*` (§23). Unlike
/// [`FixedClock`], a test can move time forward with [`advance`](Self::advance)
/// or pin it with [`set`](Self::set); `now` reads the shared counter and
/// `sleep` advances it by the requested delay (no real waiting), so
/// time-dependent control flow runs deterministically and instantly.
///
/// Method ids follow the standard `effect://time` registration order
/// (`0 = now`, `1 = sleep`); any other method also returns the current `now`.
/// The clock is `Clone` (shares one counter) so the test and the registered
/// driver observe the same time.
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
            // sleep: advance the virtual clock instead of waiting, then return.
            1 => {
                let ms = input
                    .as_map()
                    .and_then(|m| m.get("millis"))
                    .and_then(|v| v.as_int())
                    .or_else(|| input.as_int())
                    .unwrap_or(0)
                    .max(0);
                self.advance(ms);
                Ok(Outcome::Done(Value::Null))
            }
            // now (and any other method): read the shared counter.
            _ => Ok(Outcome::Done(Value::Int(self.now()))),
        }
    }
}

/// Wraps any [`Driver`] and injects a crash after a fixed number of successful
/// calls (§23: "simulate a crash after the Nth Operation"). The first `n` calls
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
    pub boot: Bootstrap,
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
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
    ) -> Result<nexus_types::ResourceName, nexus_kernel::BootstrapError> {
        self.boot.register_effect(
            path,
            &[nexus_kernel::MethodSpec::new(
                "invoke",
                nexus_types::Purity::Effectful,
                nexus_kernel::MethodSpec::UNARY_ASYNC,
            )],
            driver,
        )
    }
}

/// Replay classification of a Process's recorded facts (§15.1). Mirrors what
/// recovery would decide; useful to assert determinism in tests.
pub fn replay_report(
    facts: &FactSink,
    process: ProcessId,
) -> Result<nexus_kernel::RecoveryReport, nexus_kernel::FactError> {
    nexus_kernel::recover_process(facts, process).map(|(report, _, _)| report)
}

/// The "why-not" explanation for one Operation (§23). A pure projection over the
/// Process's Facts (§9.1) — it reads the recorded `decision`, `taint`, and
/// outcome, and never re-runs anything. Answers: did the Operation reach a
/// decision, what was it, was its input tainted / protected, and a
/// human-readable summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhyNot {
    /// The Operation being explained.
    pub op: nexus_types::OperationId,
    /// The recorded decision tag (the proximate verdict).
    pub decision: nexus_types::DecisionTag,
    /// Whether the input lineage touched a protected source (§21.5) — the
    /// structural reason an outbound Operation is denied.
    pub tainted_protected: bool,
    /// Whether the input lineage touched untrusted content (model / inbound /
    /// fetched) — the memory-poison / injection signal (§21.5).
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
/// Facts (§23 why-not / §9.1 projection).
///
/// Returns `None` if no Fact for `op` exists (the Operation never reached a
/// decision — e.g. its graph cursor was never reached). Otherwise returns a
/// [`WhyNot`] describing the decision and the taint lineage that drove it. This
/// is deliberately a *pure* read over Facts: the same defense lineage
/// (`Fact.taint`, `Fact.decision`) the data plane recorded at decision time.
pub fn why_not(facts: &[nexus_types::Fact], op: nexus_types::OperationId) -> Option<WhyNot> {
    use nexus_types::DecisionTag;
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
            let mut s = "rejected by a residual policy check (§21)".to_string();
            if tainted_protected {
                s.push_str(
                    "; its input lineage touched a protected source, so an \
                            outbound flow is structurally denied (§21.5)",
                );
            } else if tainted_untrusted {
                s.push_str("; its input carried untrusted content (model/inbound/fetched) (§21.5)");
            }
            s
        }
        DecisionTag::DriverError => "the driver returned an error".to_string(),
        DecisionTag::Timeout => "the operation timed out".to_string(),
        DecisionTag::Cancelled => "the operation was cancelled".to_string(),
        DecisionTag::Quarantined => {
            "held in quarantine as an unsafe replay, pending an operator decision (§15.3)"
                .to_string()
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
    use nexus_graph::{DoNode, OperationTemplate, StepRef};
    use nexus_types::OutputMode;

    fn run_prog(name: nexus_types::ResourceName) -> DoNode {
        run_prog_with(name, Value::Null)
    }

    fn run_prog_with(name: nexus_types::ResourceName, input: Value) -> DoNode {
        DoNode::Op(OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        })
    }

    #[tokio::test]
    async fn scripted_driver_returns_queued_outcomes() {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("model"));
        driver.enqueue_done(Value::Str("first".into()));
        let name = sim
            .scripted_effect("effect://model/x", driver.clone())
            .unwrap();
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform").unwrap();
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        let out = ex.eval(&run_prog(name)).await;
        assert_eq!(out, Outcome::Done(Value::Str("first".into())));
        assert_eq!(driver.calls().len(), 1);
    }

    #[tokio::test]
    async fn injected_failure_routes_through_or_else_recovery_step() {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("primary"));
        driver.enqueue(Outcome::Fail(nexus_types::Failure::Cancelled));
        let name = sim
            .scripted_effect("effect://primary/fallible", driver.clone())
            .unwrap();
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform").unwrap();
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        ex.steps.install(sim.boot.root, "fallback", |v, _| match v {
            Value::Str(reason) if reason.contains("cancelled") => {
                DoNode::pure(Value::Str("fallback".into()))
            }
            other => DoNode::pure(Value::Str(format!("unexpected recovery input: {other:?}"))),
        });

        let prog = run_prog(name).or_else(StepRef::new(sim.boot.root, "fallback"));
        let out = ex.eval(&prog).await;

        assert_eq!(out, Outcome::Done(Value::Str("fallback".into())));
        assert_eq!(driver.calls().len(), 1);
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].decision, nexus_types::DecisionTag::DriverError);
    }

    #[tokio::test]
    async fn replay_report_counts_recorded_facts() {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("m"));
        driver.enqueue_done(Value::Int(1));
        let name = sim.scripted_effect("effect://m/x", driver).unwrap();
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform").unwrap();
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        ex.eval(&run_prog(name)).await;
        let report = replay_report(&sim.boot.kernel.facts, sim.boot.root).unwrap();
        assert_eq!(
            report.skipped, 1,
            "one completed effect ⇒ skipped on replay"
        );
    }

    #[tokio::test]
    async fn budget_denial_records_fact_without_calling_scripted_driver() {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("costly"));
        driver.enqueue_done(Value::Int(99));
        let name = sim
            .boot
            .register_effect_with_cost(
                "effect://costly/call",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                driver.clone(),
                nexus_types::CostModel {
                    flat_micro_usd: 1_000,
                    ..Default::default()
                },
            )
            .unwrap();
        sim.boot.kernel.processes.set_budget_spec(
            sim.boot.root,
            nexus_types::BudgetSpec {
                daily_micro_usd: Some(999),
                ..Default::default()
            },
        );
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform").unwrap();
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);

        let out = ex
            .eval(&run_prog_with(name, Value::Str("pay".into())))
            .await;

        match out {
            Outcome::Fail(nexus_types::Failure::BudgetExhausted { dim }) => {
                assert_eq!(dim, "daily_micro_usd");
            }
            other => panic!("expected budget denial, got {other:?}"),
        }
        assert!(
            driver.calls().is_empty(),
            "budget denial must happen before the scripted driver is invoked"
        );
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].decision,
            nexus_types::DecisionTag::RejectedByPolicy
        );
        assert_eq!(facts[0].handle, handle);
        assert_ne!(facts[0].resource, nexus_types::ResourceId::new(0));
        assert_eq!(
            facts[0].replay,
            nexus_types::ReplayClass::NonIdempotentEffect
        );
    }

    #[tokio::test]
    async fn idempotent_duplicate_short_circuits_driver_and_records_attempt() {
        let sim = Sim::new();
        let driver = Arc::new(ScriptedDriver::new("idempotent"));
        driver.enqueue_done(Value::Str("created".into()));
        let name = sim
            .boot
            .register_effect(
                "effect://orders/create",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Idempotent,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                driver.clone(),
            )
            .unwrap();
        let handle = sim.boot.open_for(sim.boot.root, &name, "perform").unwrap();
        let ex = sim.boot.kernel.executor_for(sim.boot.root);
        ex.bind_handle(name.clone(), handle);
        let mut input = std::collections::BTreeMap::new();
        input.insert("_idem_key".into(), Value::Str("order-42".into()));
        let prog = run_prog_with(name, Value::Map(input));

        let first = ex.eval(&prog).await;
        let second = ex.eval(&prog).await;

        assert_eq!(first, Outcome::Done(Value::Str("created".into())));
        assert_eq!(second, Outcome::Done(Value::Str("created".into())));
        assert_eq!(
            driver.calls().len(),
            1,
            "the replayed node must use the idempotency cache"
        );
        let facts = sim.boot.kernel.facts.facts_of(sim.boot.root).unwrap();
        assert_eq!(facts.len(), 1, "same OperationId updates the same Fact");
        assert_eq!(facts[0].decision, nexus_types::DecisionTag::Ok);
        assert_eq!(facts[0].replay, nexus_types::ReplayClass::IdempotentEffect);
    }

    #[tokio::test]
    async fn sim_clock_now_reflects_advance_and_set() {
        let ctx = DriverContext::new(nexus_types::IdentityRef::ROOT, ProcessId::new(1));
        let clock = SimClock::new(1_000);
        // `now` (method 0) reads the starting time.
        let out = clock
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Int(1_000)));

        // `advance` moves it forward; `now` sees the new time.
        assert_eq!(clock.advance(500), 1_500);
        let out = clock
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Int(1_500)));

        // `sleep` (method 1) advances virtual time without real waiting.
        let mut m = std::collections::BTreeMap::new();
        m.insert("millis".into(), Value::Int(250));
        let out = clock
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Null));
        assert_eq!(clock.now(), 1_750);

        // `set` pins absolute time.
        clock.set(42);
        assert_eq!(clock.now(), 42);
    }

    #[tokio::test]
    async fn crash_after_n_stops_at_the_nth_call() {
        let ctx = DriverContext::new(nexus_types::IdentityRef::ROOT, ProcessId::new(1));
        let crasher = CrashAfter::arc(Arc::new(nexus_kernel::EchoDriver), 2);
        // First two calls delegate to EchoDriver and succeed.
        let a = crasher
            .call(MethodId::new(0), Value::Int(1), OutputMode::Unary, &ctx)
            .await;
        let b = crasher
            .call(MethodId::new(0), Value::Int(2), OutputMode::Unary, &ctx)
            .await;
        assert_eq!(a.unwrap(), Outcome::Done(Value::Int(1)));
        assert_eq!(b.unwrap(), Outcome::Done(Value::Int(2)));
        assert!(!crasher.has_crashed());
        assert_eq!(crasher.calls_made(), 2);

        // Third call crashes (distinctive transport error), and so does the next.
        let c = crasher
            .call(MethodId::new(0), Value::Int(3), OutputMode::Unary, &ctx)
            .await;
        assert!(
            matches!(c, Err(DriverError::Transport(_))),
            "Nth+1 call crashes"
        );
        assert!(crasher.has_crashed());
        let d = crasher
            .call(MethodId::new(0), Value::Int(4), OutputMode::Unary, &ctx)
            .await;
        assert!(d.is_err(), "stays crashed after the crash point");
    }

    #[test]
    fn why_not_explains_a_denied_fact() {
        use nexus_types::ids::NodeId;
        use nexus_types::{
            DecisionTag, Fact, HandleId, IdentityRef, MethodId, OperationId, OutcomeRef, Path,
            ProcessId, ReplayClass, ResourceId, TaintSet, TaintSource, Timestamp, ValueRef,
        };

        let op = OperationId::new(ProcessId::new(7), NodeId::new(3), 0);
        // A residual policy rejected an outbound op whose input touched the vault.
        let mut taint = TaintSet::of(TaintSource::ModelOutput);
        taint.add(TaintSource::Protected {
            path: Path::parse("state://vault/alice/x").unwrap(),
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

        let why = why_not(&[fact], op).expect("a recorded fact yields a WhyNot");
        assert_eq!(why.decision, DecisionTag::RejectedByPolicy);
        assert!(!why.was_allowed());
        assert!(why.tainted_protected, "lineage touched a protected source");
        assert!(why.tainted_untrusted, "lineage also carried model output");
        assert!(
            why.explanation.contains("protected source"),
            "{}",
            why.explanation
        );

        // No Fact for an unrelated op ⇒ no explanation (cursor never reached it).
        let other = OperationId::new(ProcessId::new(7), NodeId::new(99), 0);
        assert!(why_not(&[], other).is_none());
    }
}
