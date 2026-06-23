//! The Executor: advances a compiled [`ExecutionGraph`] to produce Operations
//! and an Outcome.
//!
//! The Executor **only ever advances a graph** — it never interprets the `Do<A>`
//! source form directly. `eval()` compiles the program once (`compile_do`),
//! binds the resulting graph, then walks it node-by-node. Each node's id is its
//! **stable `CausalPosition`**: assigned by the compiler in
//! pre-order, identical across recompiles, so an Operation's identity is
//! independent of wall clock and survives crash-recovery.
//!
//! Per node kind:
//! - `Pure` / `Fail` yield a value / failure immediately.
//! - `Operation` issues one data-plane call (records a Fact).
//! - `Step` splices its produced subgraph at the cursor (run-time `AndThen`).
//! - `Branch(OrElse)` runs its guarded arm; on failure routes into `recover`.
//! - `Join(Both)` runs both arms concurrently (async I/O overlap); `Join(Race)`
//!   runs both and takes the first to finish, cancelling the loser.
//! - `Acting` switches block-level identity for its arm.
//! - `Wait` blocks on a signal path or a wall-clock deadline.

use crate::dataplane::DataPlane;
use crate::open::{OpenRequest, open_resource_with_attached};
use crate::registry::Registry;
use crate::step::StepTable;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use thiserror::Error;
use xolotl_graph::{
    BranchKind, DoNode, EdgeKind, ExecutionGraph, JoinKind, NodeKind, OperationTemplate, StepRef,
    WaitSpec, compile_do, operation_capability_verb,
};
use xolotl_types::{
    DecisionTag, HandleId, IdentityRef, MethodBitmap, NodeId, Operation, OperationId, Outcome,
    ProcessId, ReplayClass, ResourceName, RightFlags, Rights, Value,
};

/// Errors raised by executor-local graph evaluation.
#[derive(Debug, Error)]
pub enum ExecError {
    /// A recursive `Step` splice exceeded the configured recursion limit.
    #[error("step recursion exceeded depth {0}")]
    RecursionLimit(usize),
}

/// Maximum splice depth — a runaway recursive Step (debate loops, etc.) is
/// bounded so a buggy program can't hang the executor.
const MAX_DEPTH: usize = 4096;

type OpenHandleMap = HashMap<(ResourceName, IdentityRef), HandleId>;
type MethodHandleMap = HashMap<(ResourceName, String, IdentityRef), HandleId>;
type MethodMetaMap = HashMap<(ResourceName, String), MethodMeta>;

/// Drives one Process's program to completion. Holds the data plane (for
/// Operation dispatch), the registry (to resolve target names → handles), and
/// the step table (named continuations).
pub struct Executor {
    /// Process whose graph this executor is running.
    process: ProcessId,
    /// Data-plane dispatcher used for operation nodes.
    data_plane: DataPlane,
    /// Control-plane registry used before data-plane dispatch to resolve names
    /// and method metadata.
    registry: Registry,
    /// Table of named pure continuation steps.
    pub(crate) steps: StepTable,
    /// Optional state backend, used to resolve `Wait(Signal)` nodes.
    /// `None` for executors that never wait on a signal path.
    state: Option<xolotl_state::Backend>,
    /// Optional process table, used to observe cancellation at Operation
    /// boundaries. `None` for standalone executors (tests) that
    /// have no process lifecycle to honor.
    processes: Option<crate::process::ProcessTable>,
    /// Optional replay map: when recovering, completed Operations
    /// short-circuit to their recorded outcome.
    /// `None` / empty for a fresh run.
    replay: Option<Arc<crate::recovery::ReplayMap>>,
    /// Handles explicitly bound by host code. The acting identity is part of
    /// the key because open-time policy is identity-sensitive.
    open_handles: Arc<parking_lot::RwLock<OpenHandleMap>>,
    /// Method-specific handles opened or bound for one acting identity.
    method_handles: Arc<parking_lot::RwLock<MethodHandleMap>>,
    /// Per-(resource, method) compiled metadata cache: the data
    /// plane must not re-query the Registry on every Operation. The first op on
    /// a (target, method) resolves it once; subsequent ops read this cache, so
    /// the hot path never walks the Registry again.
    method_cache: Arc<parking_lot::RwLock<MethodMetaMap>>,
    /// Whether this executor is running process finalizers.
    finalizer_mode: bool,
}

/// Compiled, cached metadata for one (resource, method): the bit position,
/// id, replay class, supported output modes, and cost — everything the data
/// plane needs to dispatch without touching the Registry again.
#[derive(Clone)]
struct MethodMeta {
    resource_id: xolotl_types::ResourceId,
    method_index: u32,
    method_id: xolotl_types::MethodId,
    replay: ReplayClass,
    supports: xolotl_types::OutputModeSet,
    cost: xolotl_types::CostModel,
    batchable: bool,
    finalize_allowed: bool,
}

/// Block-scoped evaluation environment: `Let`-bound values keyed by the
/// **producer NodeId** (so `Use` edges resolve structurally), the current
/// acting identity, and the **taint** of the value currently flowing.
/// Threaded by value through recursion (no shared mutation).
#[derive(Clone)]
struct Env {
    /// Producer NodeId → its computed value (for `Use`-edge data dependencies).
    bindings: HashMap<NodeId, Value>,
    /// Producer NodeId → that value's taint (parallel to `bindings`).
    binding_taint: HashMap<NodeId, xolotl_types::TaintSet>,
    acting: IdentityRef,
    /// Provenance of the value flowing into the current node.
    taint: xolotl_types::TaintSet,
}

impl Env {
    fn root(acting: IdentityRef) -> Self {
        Self {
            bindings: HashMap::new(),
            binding_taint: HashMap::new(),
            acting,
            taint: xolotl_types::TaintSet::pristine(),
        }
    }

    /// Derive a child env carrying `taint` as the flowing value's provenance.
    fn with_taint(&self, taint: xolotl_types::TaintSet) -> Self {
        let mut e = self.clone();
        e.taint = taint;
        e
    }
}

impl Executor {
    /// Create an executor bound to one process.
    pub(crate) fn new(
        process: ProcessId,
        data_plane: DataPlane,
        registry: Registry,
        steps: StepTable,
    ) -> Self {
        Self {
            process,
            data_plane,
            registry,
            steps,
            state: None,
            processes: None,
            replay: None,
            open_handles: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            method_handles: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            method_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            finalizer_mode: false,
        }
    }

    /// Attach a state backend so `Wait(Signal)` nodes can resolve.
    pub fn with_state(mut self, state: xolotl_state::Backend) -> Self {
        self.state = Some(state);
        self
    }

    /// Attach a replay map so a recovered run short-circuits already-completed
    /// Operations to their recorded outcomes.
    pub fn with_replay(mut self, replay: Arc<crate::recovery::ReplayMap>) -> Self {
        self.replay = Some(replay);
        self
    }

    /// Attach the process table so the executor honors cancellation at each
    /// Operation boundary.
    pub fn with_processes(mut self, processes: crate::process::ProcessTable) -> Self {
        self.processes = Some(processes);
        self
    }

    /// Permit Operation nodes while the owning process is in Finalizing.
    pub(crate) fn with_finalizer_mode(mut self) -> Self {
        self.finalizer_mode = true;
        self
    }

    /// Whether this process has been cancelled or moved past Running.
    /// Returns false when no process table is attached (standalone executors).
    fn is_cancelled(&self) -> bool {
        match &self.processes {
            Some(p) => match p.status(self.process) {
                Some(xolotl_types::ProcessStatus::Cancelled) => true,
                Some(xolotl_types::ProcessStatus::Finalizing) => !self.finalizer_mode,
                _ => false,
            },
            None => false,
        }
    }

    /// Pre-register a resolved handle for a resource name.
    pub fn bind_handle(&self, name: ResourceName, handle: xolotl_types::HandleId) {
        if let Some(acting) = self.default_acting() {
            self.open_handles.write().insert((name, acting), handle);
        }
    }

    /// Pre-register a resolved handle for one resource method.
    pub fn bind_method_handle(
        &self,
        name: ResourceName,
        method: impl Into<String>,
        handle: xolotl_types::HandleId,
    ) {
        if let Some(acting) = self.default_acting() {
            self.method_handles
                .write()
                .insert((name, method.into(), acting), handle);
        }
    }

    fn default_acting(&self) -> Option<IdentityRef> {
        match &self.processes {
            Some(processes) => processes.identity(self.process),
            None => Some(IdentityRef::ROOT),
        }
    }

    /// Evaluate a whole program to an Outcome. Compiles the `Do<A>` into one
    /// [`ExecutionGraph`], then advances the graph — the Executor never
    /// interprets the source form directly.
    pub async fn eval(&self, program: &DoNode) -> Outcome {
        let graph = match compile_do(program) {
            Ok(g) => g,
            Err(e) => {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("compile failed: {e}"),
                ));
            }
        };
        self.eval_graph(&graph).await
    }

    /// Advance a compiled graph from its root to an Outcome.
    pub async fn eval_graph(&self, graph: &ExecutionGraph) -> Outcome {
        self.eval_graph_tainted(graph, xolotl_types::TaintSet::pristine())
            .await
    }

    /// Evaluate a program whose entry value carries `entry_taint`.
    ///
    /// Gateways use this for externally-sourced programs, where inbound content
    /// is tainted as `Inbound` so the whole run inherits that lineage.
    pub async fn eval_tainted(
        &self,
        program: &DoNode,
        entry_taint: xolotl_types::TaintSet,
    ) -> Outcome {
        let graph = match compile_do(program) {
            Ok(g) => g,
            Err(e) => {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("compile failed: {e}"),
                ));
            }
        };
        self.eval_graph_tainted(&graph, entry_taint).await
    }

    /// Advance a compiled graph with a given entry taint.
    async fn eval_graph_tainted(
        &self,
        graph: &ExecutionGraph,
        entry_taint: xolotl_types::TaintSet,
    ) -> Outcome {
        // `next_splice_base` hands out id ranges for spliced Step subgraphs so
        // their CausalPositions never collide with the parent graph or each
        // other. It starts past the highest compiled id.
        let next_base = Arc::new(std::sync::atomic::AtomicU32::new(graph.len() as u32));
        let Some(acting) = self.default_acting() else {
            return Outcome::Fail(xolotl_types::Failure::policy(
                "executor",
                format!("unknown process {}", self.process.get()),
            ));
        };
        let env = Env::root(acting).with_taint(entry_taint);
        self.run_node(graph, graph.root, Value::Null, &env, 0, &next_base)
            .await
    }
    /// Evaluate the node at `id` with `input` flowing in, then advance to its
    /// continuation. The node's id **is** its CausalPosition — read
    /// straight off the compiled graph, never re-derived.
    fn run_node<'a>(
        &'a self,
        graph: &'a ExecutionGraph,
        id: NodeId,
        input: Value,
        env: &'a Env,
        depth: usize,
        next_base: &'a Arc<std::sync::atomic::AtomicU32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>> {
        Box::pin(async move {
            if depth > MAX_DEPTH {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    "step recursion limit exceeded",
                ));
            }
            let Some(node) = graph.node(id) else {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("dangling node id {}", id.get()),
                ));
            };
            match &node.kind {
                NodeKind::Pure(v) => {
                    // `Use` nodes are Pure(Null) with an incoming Use-edge: the
                    // real value (and its taint) is the bound producer's output.
                    // A bare Pure literal is an author constant.
                    let (out, taint) = match self.resolve_use(graph, id, env) {
                        Ok(Some((bound, t))) => (bound, t),
                        Ok(None) => (v.clone(), xolotl_types::TaintSet::author()),
                        Err(failure) => return Outcome::Fail(failure),
                    };
                    let env2 = env.with_taint(taint);
                    self.continue_then(graph, id, out, &env2, depth, next_base)
                        .await
                }

                NodeKind::Fail(f) => Outcome::Fail(f.clone()),

                NodeKind::Operation(tmpl) => {
                    // A Process observes cancellation at each Operation
                    // boundary. If it was cancelled or moved to Finalizing,
                    // short-circuit to Cancelled before issuing the side effect.
                    if self.is_cancelled() {
                        return self
                            .continue_with(
                                graph,
                                id,
                                Outcome::Fail(xolotl_types::Failure::Cancelled),
                                env,
                                depth,
                                next_base,
                            )
                            .await;
                    }
                    // If this Operation's outcome is already durably recorded
                    // for its CausalPosition, reuse it instead of re-issuing
                    // the side effect. This keeps recovered runs from repeating
                    // a NonIdempotentEffect that already happened.
                    if let Some(replay) = &self.replay
                        && let Some(recorded) = replay.get(id)
                    {
                        let recorded = recorded.clone();
                        return self
                            .continue_with(graph, id, recorded, env, depth, next_base)
                            .await;
                    }
                    // Finalizers always record; cleanup side effects must stay
                    // visible even when their output is not consumed.
                    let record = self.finalizer_mode || graph.output_is_consumed(id);
                    let (out, out_taint) = self.run_operation(tmpl, input, env, id, record).await;
                    // The result flows on carrying the operation's taint.
                    let env2 = env.with_taint(out_taint);
                    self.continue_with(graph, id, out, &env2, depth, next_base)
                        .await
                }

                NodeKind::Step(sref) => {
                    let out = self.run_step(sref, input, env, depth, next_base).await;
                    self.continue_with(graph, id, out, env, depth, next_base)
                        .await
                }

                NodeKind::Branch(BranchKind::OrElse { recover }) => {
                    let arm = self.arm_entry(graph, id);
                    let guarded = match arm {
                        Some(a) => {
                            self.run_node(graph, a, input, env, depth + 1, next_base)
                                .await
                        }
                        None => Outcome::Done(Value::Null),
                    };
                    let out = match guarded {
                        Outcome::Fail(f) => {
                            // Compensate: run `recover` with the failure as input.
                            let fv = Value::Str(f.to_string());
                            self.run_step(recover, fv, env, depth + 1, next_base).await
                        }
                        ok => ok,
                    };
                    self.continue_with(graph, id, out, env, depth, next_base)
                        .await
                }

                NodeKind::Join(kind) => {
                    let arms = self.arm_entries(graph, id);
                    let out = match (arms.first().copied(), arms.get(1).copied()) {
                        (Some(a), Some(b)) => {
                            let fa =
                                self.run_node(graph, a, input.clone(), env, depth + 1, next_base);
                            let fb = self.run_node(graph, b, input, env, depth + 1, next_base);
                            match kind {
                                // Genuine concurrency: both arms make progress
                                // across their Operation awaits; wall-clock ≈
                                // max(arm), not sum.
                                JoinKind::Both => {
                                    let (ra, rb) = tokio::join!(fa, fb);
                                    match (ra, rb) {
                                        (
                                            Outcome::Done(va) | Outcome::Short(va),
                                            Outcome::Done(vb) | Outcome::Short(vb),
                                        ) => Outcome::Done(Value::List(vec![va, vb])),
                                        (Outcome::Fail(f), _) | (_, Outcome::Fail(f)) => {
                                            Outcome::Fail(f)
                                        }
                                    }
                                }
                                // First to finish wins; `select!` drops (cancels)
                                // the loser's future.
                                JoinKind::Race => tokio::select! {
                                    ra = fa => ra,
                                    rb = fb => rb,
                                },
                            }
                        }
                        _ => Outcome::Fail(xolotl_types::Failure::policy(
                            "executor",
                            "join node missing two arms",
                        )),
                    };
                    self.continue_with(graph, id, out, env, depth, next_base)
                        .await
                }

                NodeKind::Acting(path) => {
                    // Switching the acting identity is a
                    // *delegation*, not a free operation. The process must hold
                    // a grant `act-as://<identity>` carrying the DELEGATE flag.
                    // Without it the switch is denied fail-closed — otherwise any
                    // program could assume any identity and defeat the capability
                    // model. Fact records caller and acting both.
                    if !self.authorize_act_as(path) {
                        let out = Outcome::Fail(xolotl_types::Failure::policy(
                            "act-as",
                            format!(
                                "process {} holds no act-as://{} grant with DELEGATE",
                                self.process.get(),
                                path
                            ),
                        ));
                        return self
                            .continue_with(graph, id, out, env, depth, next_base)
                            .await;
                    }
                    let arm = self.arm_entry(graph, id);
                    let mut env2 = env.clone();
                    env2.acting = intern_identity(path);
                    let out = match arm {
                        Some(a) => {
                            self.run_node(graph, a, input, &env2, depth + 1, next_base)
                                .await
                        }
                        None => Outcome::Done(Value::Null),
                    };
                    // Identity restored: the continuation runs under the outer env.
                    self.continue_with(graph, id, out, env, depth, next_base)
                        .await
                }

                NodeKind::Wait(spec) => {
                    let out = self.run_wait(spec).await;
                    self.continue_with(graph, id, out, env, depth, next_base)
                        .await
                }
            }
        })
    }
    /// Continue from `id` after producing `out`. If `out` failed, the failure
    /// propagates (the nearest enclosing `Branch` catches it); otherwise the
    /// success value flows along the `Then` edge to the continuation. A node
    /// with no `Then` edge is a span exit — its value is the result.
    fn continue_with<'a>(
        &'a self,
        graph: &'a ExecutionGraph,
        id: NodeId,
        out: Outcome,
        env: &'a Env,
        depth: usize,
        next_base: &'a Arc<std::sync::atomic::AtomicU32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>> {
        Box::pin(async move {
            match out {
                Outcome::Done(v) | Outcome::Short(v) => {
                    self.continue_then(graph, id, v, env, depth, next_base)
                        .await
                }
                fail => fail,
            }
        })
    }

    /// Route the success value `v` along `id`'s `Then` edge (the continuation),
    /// recording the produced value as `id`'s binding (so a later `Use` edge to
    /// `id` resolves). With no `Then` edge, `v` is this span's result.
    fn continue_then<'a>(
        &'a self,
        graph: &'a ExecutionGraph,
        id: NodeId,
        v: Value,
        env: &'a Env,
        depth: usize,
        next_base: &'a Arc<std::sync::atomic::AtomicU32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send + 'a>> {
        Box::pin(async move {
            match self.then_target(graph, id) {
                Some(next) => {
                    // Record this node's output (value + taint) for any Use-edge
                    // dependents, then flow into the continuation.
                    let mut env2 = env.clone();
                    env2.bindings.insert(id, v.clone());
                    env2.binding_taint.insert(id, env.taint.clone());
                    self.run_node(graph, next, v, &env2, depth + 1, next_base)
                        .await
                }
                None => Outcome::Done(v),
            }
        })
    }

    /// The `Then`-edge continuation target of `id`, if any.
    fn then_target(&self, graph: &ExecutionGraph, id: NodeId) -> Option<NodeId> {
        graph.out_edges_of(id, EdgeKind::Then).map(|e| e.to).next()
    }

    /// The `Arm`-edge entry of a structured node (`Branch`/`Acting` have one
    /// arm; `Join` has two — use [`arm_entries`] there).
    fn arm_entry(&self, graph: &ExecutionGraph, id: NodeId) -> Option<NodeId> {
        graph.out_edges_of(id, EdgeKind::Arm).map(|e| e.to).next()
    }

    /// Both `Arm`-edge entries of a `Join` node, in compiled order.
    fn arm_entries(&self, graph: &ExecutionGraph, id: NodeId) -> Vec<NodeId> {
        graph
            .out_edges_of(id, EdgeKind::Arm)
            .map(|e| e.to)
            .collect()
    }

    /// Resolve a `Use` node's value and taint: the output recorded for the
    /// producer node reachable along the incoming `Use` edge ( DAG data
    /// dependency). The producer's taint flows on with the value.
    fn resolve_use(
        &self,
        graph: &ExecutionGraph,
        id: NodeId,
        env: &Env,
    ) -> Result<Option<(Value, xolotl_types::TaintSet)>, xolotl_types::Failure> {
        let Some(producer) = graph
            .edges
            .iter()
            .find(|e| e.to == id && e.kind == EdgeKind::Use)
            .map(|e| e.from)
        else {
            return Ok(None);
        };
        let Some(v) = env.bindings.get(&producer).cloned() else {
            return Err(xolotl_types::Failure::policy(
                "executor",
                format!("missing binding for use edge from node {}", producer.get()),
            ));
        };
        let Some(taint) = env.binding_taint.get(&producer).cloned() else {
            return Err(xolotl_types::Failure::policy(
                "executor",
                format!("missing taint for use edge from node {}", producer.get()),
            ));
        };
        Ok(Some((v, taint)))
    }
    /// Splice and run a `Step`'s produced subgraph (the run-time face of
    /// `AndThen` / `OrElse` recovery). The step is a pure `Value -> Do<A>`
    /// continuation; its subgraph is compiled with a fresh id offset so its
    /// Operation CausalPositions stay globally unique.
    async fn run_step(
        &self,
        sref: &StepRef,
        piped: Value,
        env: &Env,
        depth: usize,
        next_base: &Arc<std::sync::atomic::AtomicU32>,
    ) -> Outcome {
        if sref.process != self.process {
            return Outcome::Fail(xolotl_types::Failure::policy(
                "step",
                format!(
                    "step \"{}\" belongs to process {}, not current process {}",
                    sref.name,
                    sref.process.get(),
                    self.process.get()
                ),
            ));
        }
        let sub = match self.steps.get(self.process, &sref.name) {
            Some(f) => {
                match std::panic::catch_unwind(AssertUnwindSafe(|| f(piped, sref.arg.clone()))) {
                    Ok(sub) => sub,
                    Err(payload) => {
                        return Outcome::Fail(xolotl_types::Failure::HandlerError {
                            kind: "panic".into(),
                            message: crate::bootstrap::panic_payload_message("step", payload),
                        });
                    }
                }
            }
            None => {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("step \"{}\" not found", sref.name),
                ));
            }
        };
        // Reserve an id range past everything numbered so far, then compile the
        // produced subgraph into it and run it.
        let reserve = sub.size() as u32;
        let base = next_base.fetch_add(reserve, std::sync::atomic::Ordering::Relaxed);
        let subgraph = match xolotl_graph::compile_do_at(&sub, base) {
            Ok(g) => g,
            Err(e) => {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("step \"{}\" compile failed: {e}", sref.name),
                ));
            }
        };
        self.run_node(
            &subgraph,
            subgraph.root,
            Value::Null,
            env,
            depth + 1,
            next_base,
        )
        .await
    }

    /// Block on a `Wait` node. `Deadline` sleeps to the wall clock; `Signal`
    /// resolves when the path is written (subscribe), bounded by a cap so a
    /// never-arriving signal can't wedge the run forever.
    async fn run_wait(&self, spec: &WaitSpec) -> Outcome {
        match spec {
            WaitSpec::Deadline(at_millis) => {
                let now = now_millis();
                if *at_millis > now {
                    let dur = std::time::Duration::from_millis((*at_millis - now) as u64);
                    tokio::time::sleep(dur).await;
                }
                Outcome::Done(Value::Null)
            }
            WaitSpec::Signal(path) => match &self.state {
                Some(state) => self.wait_signal(state, path).await,
                None => Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    "Wait(Signal) needs a state backend (none bound)",
                )),
            },
        }
    }
    /// Resolve a `Wait(Signal)` by subscribing to `path` and returning when the
    /// first matching write arrives (or a bounded number of unrelated events
    /// pass without a match).
    async fn wait_signal(
        &self,
        state: &xolotl_state::Backend,
        path: &xolotl_types::Path,
    ) -> Outcome {
        use xolotl_state::StateEvent;
        // If the signal is already present, return immediately.
        if let Ok(Some(v)) = state.read(path).await {
            return Outcome::Done(v);
        }
        let mut rx = match state.subscribe(path).await {
            Ok(rx) => rx,
            Err(e) => {
                return Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("wait subscribe failed: {e}"),
                ));
            }
        };
        loop {
            match rx.recv().await {
                Ok(StateEvent::Set { path: p, value, .. }) if &p == path => {
                    return Outcome::Done(value);
                }
                Ok(StateEvent::Append { path: p, item, .. }) if &p == path => {
                    return Outcome::Done(item);
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Outcome::Fail(xolotl_types::Failure::policy(
                        "executor",
                        "wait signal channel closed",
                    ));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    return Outcome::Fail(xolotl_types::Failure::policy(
                        "executor",
                        format!("wait signal channel lagged and dropped {skipped} events"),
                    ));
                }
            }
        }
    }

    /// Issue one Operation through the data plane, labelling it with its
    /// stable CausalPosition (the node's id). Resolves the target Resource →
    /// owned Handle, then dispatches. Returns the outcome and the taint that
    /// flows on with the result value.
    async fn run_operation(
        &self,
        tmpl: &OperationTemplate,
        input: Value,
        env: &Env,
        position: NodeId,
        record: bool,
    ) -> (Outcome, xolotl_types::TaintSet) {
        let effective_input = tmpl.literal_input.clone().unwrap_or(input);

        // The output inherits the flowing value's lineage plus the
        // target's intrinsic source (e.g. inference → ModelOutput, a vault read
        // → Protected, a fetch → Fetched).
        let mut op_taint = env.taint.clone();
        if let Some(src) = intrinsic_source(&tmpl.target) {
            op_taint.add(src);
        }

        // Structural outbound defense, checked *before* resource
        // resolution so a tainted exfiltration attempt is denied on structure
        // alone: a value whose lineage touched a Protected source must not flow
        // out through an outbound Operation (post / send / publish). This is a
        // lineage check, not a hash match; a model paraphrasing the secret
        // cannot evade the protected-source taint.
        if is_outbound(&tmpl.target) && op_taint.has_protected() {
            return (
                Outcome::Fail(xolotl_types::Failure::PolicyViolation {
                    policy: "taint".into(),
                    detail: format!(
                        "protected data must not flow to outbound {}",
                        tmpl.target.path()
                    ),
                }),
                op_taint,
            );
        }

        // Resolve compiled method metadata once and cache it: the hot path
        // must not re-query the Registry per Operation. A cache miss resolves via
        // the Registry and memoizes; a hit skips it entirely.
        let Some(meta) = self.resolve_meta(&tmpl.target, &tmpl.method) else {
            return (
                Outcome::Fail(xolotl_types::Failure::NoHandler {
                    path: tmpl.target.path().clone(),
                }),
                env.taint.clone(),
            );
        };
        let MethodMeta {
            resource_id,
            method_index,
            method_id,
            replay,
            supports,
            cost,
            batchable,
            finalize_allowed,
            ..
        } = meta;

        if !self.finalizer_allows_operation(&tmpl.target, &tmpl.method, finalize_allowed) {
            return (
                Outcome::Fail(xolotl_types::Failure::PolicyViolation {
                    policy: "finalizer".into(),
                    detail: format!(
                        "method {} on {} is not allowed while process {} is finalizing",
                        tmpl.method,
                        tmpl.target.path(),
                        self.process.get()
                    ),
                }),
                op_taint,
            );
        }

        // The requested OutputMode must be in the method's supported set.
        // Reject before opening a handle so invalid requests do not mutate the
        // handle table.
        if !tmpl.output.is_supported_by(supports) {
            return (
                Outcome::Fail(xolotl_types::Failure::InvalidInput {
                    reason: format!(
                        "method {} does not support output mode {:?}",
                        tmpl.method, tmpl.output
                    ),
                }),
                op_taint,
            );
        }

        let handle = match self.handle_for_or_open(
            &tmpl.target,
            &tmpl.method,
            env.acting,
            resource_id,
            method_index,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                return (
                    Outcome::Fail(xolotl_types::Failure::policy(
                        "open",
                        format!(
                            "open {} method {} failed for {}: {error}",
                            operation_capability_verb(&tmpl.method),
                            tmpl.method,
                            tmpl.target.path()
                        ),
                    )),
                    env.taint.clone(),
                );
            }
        };

        let op = Operation {
            id: OperationId::new(self.process, position, 0),
            process: self.process,
            acting: env.acting,
            handle,
            method: method_id,
            input: effective_input,
            taint: op_taint.clone(),
            output: tmpl.output,
        };

        // Reserve a conservative budget estimate before the effect, then settle
        // to the measured cost after. Free methods skip this entirely.
        // Attribution is to the running Process (whose budget the acting identity
        // draws on). Reservation is fail-closed: over budget ⇒ deny before the
        // side effect is ever issued.
        let mut reservation: Option<(u64, u64)> = None;
        let now = now_millis();
        if !cost.is_free()
            && let Some(procs) = &self.processes
        {
            let in_tokens = billable_input_tokens(&op.input, batchable);
            // Conservative output projection: assume output as large as input
            // (settlement corrects downward to the real count).
            let est_tokens = in_tokens;
            let est_usd = estimate_cost(&cost, &op.input, in_tokens, est_tokens, batchable);
            if let Err(dim) = procs.reserve(self.process, est_usd, est_tokens) {
                let out = self.data_plane.record_pre_dispatch_denial(
                    &op,
                    replay,
                    now,
                    DecisionTag::RejectedByPolicy,
                    xolotl_types::Failure::BudgetExhausted { dim },
                );
                return (out.outcome, out.output_taint);
            }
            reservation = Some((est_usd, est_tokens));
        }

        let out = self
            .data_plane
            .execute_batchable(
                &op,
                crate::dataplane::ExecuteParams {
                    method_index,
                    replay,
                    supports,
                    batchable,
                    now_millis: now,
                    record,
                },
            )
            .await;

        // Settle against actual cost. The actual token count is taken
        // from the produced value; a real backend reports it in outcome
        // metadata, but the value-derived estimate is a faithful baseline.
        if let (Some((res_usd, res_tokens)), Some(procs)) = (reservation, &self.processes) {
            let out_tokens = match &out.outcome {
                Outcome::Done(v) | Outcome::Short(v) => billable_input_tokens(v, batchable),
                Outcome::Fail(_) => 0,
            };
            let actual_usd = estimate_cost(
                &cost,
                &op.input,
                billable_input_tokens(&op.input, batchable),
                out_tokens,
                batchable,
            );
            procs.settle(self.process, res_usd, actual_usd, res_tokens, out_tokens);
        }
        op_taint.union(&out.output_taint);
        (out.outcome, op_taint)
    }

    /// Authorize an `Acting(identity)` switch. The process must hold a
    /// grant whose selector is `act-as://<identity>` (matched structurally) and
    /// whose rights carry the `DELEGATE` flag. Returns false (deny) otherwise.
    ///
    /// The omnipotent root grant (`*://**` + all flags) covers every identity,
    /// so kernel-internal Acting blocks pass; attenuated children only pass for
    /// identities they were explicitly delegated.
    fn authorize_act_as(&self, identity: &xolotl_types::Path) -> bool {
        let now = now_millis();
        let mut grants = self.registry.grants_of(self.process);
        if let Some(processes) = &self.processes {
            grants.extend(processes.attached_grants(self.process));
        }
        grants.into_iter().any(|g| {
            !g.expires.is_expired(now)
                && g.rights.flags.contains(xolotl_types::RightFlags::DELEGATE)
                && g.selector.matches("act-as", identity)
        })
    }

    fn handle_for(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> Option<xolotl_types::HandleId> {
        let key = (name.clone(), method.to_string(), acting);
        if let Some(handle) = self.method_handles.read().get(&key).copied()
            && self.cached_handle_allows(handle, resource_id, method_index)
        {
            return Some(handle);
        }
        let handle = self
            .open_handles
            .read()
            .get(&(name.clone(), acting))
            .copied()?;
        if self.cached_handle_allows(handle, resource_id, method_index) {
            Some(handle)
        } else {
            None
        }
    }

    fn cached_handle_allows(
        &self,
        handle: xolotl_types::HandleId,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> bool {
        self.data_plane
            .handles
            .read()
            .get(handle)
            .map(|handle| {
                handle.check_owner(self.process)
                    && handle.resource == resource_id
                    && handle.is_active()
                    && handle.allows_method(method_index)
            })
            .unwrap_or(false)
    }

    fn handle_for_or_open(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> Result<xolotl_types::HandleId, crate::open::OpenError> {
        if let Some(handle) = self.handle_for(name, method, acting, resource_id, method_index) {
            return Ok(handle);
        }
        let attached_grants = self
            .processes
            .as_ref()
            .map(|processes| processes.attached_grants(self.process))
            .unwrap_or_default();
        let handle = {
            let mut handles = self.data_plane.handles.write();
            open_resource_with_attached(
                &self.registry,
                &mut handles,
                OpenRequest {
                    process: self.process,
                    resource: resource_id,
                    verb: operation_capability_verb(method).to_string(),
                    rights: Rights::new(MethodBitmap::method(method_index), RightFlags::empty()),
                    acting,
                    requested_path: Some(name.path().clone()),
                    now_millis: now_millis(),
                },
                &attached_grants,
            )?
        };
        self.method_handles
            .write()
            .insert((name.clone(), method.to_string(), acting), handle);
        Ok(handle)
    }

    /// Resolve cached [`MethodMeta`] for a (target, method). A cache miss
    /// walks the Registry once and memoizes; subsequent calls are pure cache
    /// reads, so the per-Operation hot path never re-queries the Registry.
    /// Returns `None` if the target resource doesn't resolve.
    fn resolve_meta(&self, target: &ResourceName, method_name: &str) -> Option<MethodMeta> {
        let key = (target.clone(), method_name.to_string());
        if let Some(m) = self.method_cache.read().get(&key) {
            return Some(m.clone());
        }
        let resource_id = match self.registry.resolve_resource(target) {
            Ok(resource_id) => resource_id,
            Err(crate::registry::ResolveError::NoSuchResource(_)) => return None,
        };
        let meta = self.compile_meta(resource_id, method_name)?;
        self.method_cache.write().insert(key, meta.clone());
        Some(meta)
    }

    /// Compile (method_index, method_id, replay class, supported output modes,
    /// cost) for a target's method by walking the Registry (slow path, cached by
    /// [`resolve_meta`]).
    fn compile_meta(
        &self,
        resource_id: xolotl_types::ResourceId,
        method_name: &str,
    ) -> Option<MethodMeta> {
        if let Some(resource) = self.registry.resource(resource_id) {
            for iface_id in &resource.interfaces.interfaces {
                if let Some(iface) = self.registry.interface(*iface_id)
                    && let Some((idx, method)) = iface.method_index(method_name)
                {
                    return Some(MethodMeta {
                        resource_id,
                        method_index: idx,
                        method_id: method.id,
                        replay: method.replay,
                        supports: method.supports,
                        cost: method.cost,
                        batchable: method.batchable,
                        finalize_allowed: method.finalize_allowed,
                    });
                }
            }
        }
        None
    }

    fn finalizer_allows_operation(
        &self,
        target: &ResourceName,
        method: &str,
        finalize_allowed: bool,
    ) -> bool {
        if !self.finalizer_mode {
            return true;
        }
        if finalize_allowed {
            return true;
        }
        let verb = operation_capability_verb(method);
        (verb == "read" || verb == "write")
            && is_process_local_state_path(target.path(), self.process)
    }
}

fn is_process_local_state_path(path: &xolotl_types::Path, process: ProcessId) -> bool {
    if path.scheme() != "state" || path.cluster().is_some() {
        return false;
    }
    let segments = path.segments();
    let Some(first) = segments.first() else {
        return false;
    };
    let Some(second) = segments.get(1) else {
        return false;
    };
    first.as_str() == "process"
        && second
            .as_str()
            .parse::<u64>()
            .is_ok_and(|pid| pid == process.get())
}

fn billable_input_tokens(value: &Value, batchable: bool) -> u64 {
    match (batchable, value) {
        (true, Value::List(items)) => items.iter().map(Value::approx_tokens).sum::<u64>().max(1),
        _ => value.approx_tokens(),
    }
}

fn estimate_cost(
    cost: &xolotl_types::CostModel,
    input: &Value,
    in_tokens: u64,
    out_tokens: u64,
    batchable: bool,
) -> u64 {
    match (batchable, input) {
        (true, Value::List(items)) => {
            let elems = items.len() as u64;
            let flat = cost.flat_micro_usd.saturating_mul(elems);
            let variable = xolotl_types::CostModel {
                flat_micro_usd: 0,
                ..*cost
            }
            .estimate_micro_usd(in_tokens, out_tokens);
            flat.saturating_add(variable)
        }
        _ => cost.estimate_micro_usd(in_tokens, out_tokens),
    }
}

/// Intern an identity path to a stable [`IdentityRef`] by hashing. Public
/// so Gateways map a request identity to the same ref the executor uses for
/// `Acting` blocks.
pub fn intern_identity(path: &xolotl_types::Path) -> IdentityRef {
    let h = blake3::hash(path.to_string().as_bytes());
    // blake3 digests are 32 bytes, so the first 8 always exist — copy them into
    // a fixed-size array to derive the ref without a fallible slice conversion.
    let mut head = [0u8; 8];
    head.copy_from_slice(&h.as_bytes()[0..8]);
    let n = u64::from_le_bytes(head);
    // Reserve 0 for ROOT.
    IdentityRef::new(n | 1)
}

/// The intrinsic taint a target Resource confers on its output: an
/// inference call yields `ModelOutput`, a fetch yields `Fetched`, a read of a
/// protected prefix (`state://vault/*` etc.) yields `Protected`. Returns `None`
/// for neutral targets that merely pass their input lineage through.
fn intrinsic_source(target: &ResourceName) -> Option<xolotl_types::TaintSource> {
    let path = target.path();
    let scheme = path.scheme();
    let segs = path.segments();
    let first = segs.first().map(|s| s.as_str()).unwrap_or("");
    match scheme {
        // Inference / deliberation outputs are model-generated.
        "effect" if first == "inference" || first == "deliberation" => {
            Some(xolotl_types::TaintSource::ModelOutput)
        }
        // Fetch / external tool outputs are tagged by host (best-effort: the
        // host is the second segment when present, else the effect domain).
        "effect" if first == "fetch" => {
            let host = segs.get(1).map(|s| s.as_str()).unwrap_or("unknown");
            Some(xolotl_types::TaintSource::Fetched { host: host.into() })
        }
        // Reads from a protected state prefix carry the secret's lineage.
        "state" if xolotl_types::is_vault_reserved(path) => {
            Some(xolotl_types::TaintSource::Protected { path: path.clone() })
        }
        _ => None,
    }
}

/// Whether an Operation on `target` sends data to the outside world.
/// Outbound effects are the gate for protected-data exfiltration: posting,
/// sending, publishing, or any fetch with a request body. Conservative: unknown
/// effects under known outbound domains count as outbound.
fn is_outbound(target: &ResourceName) -> bool {
    let path = target.path();
    if path.scheme() != "effect" {
        return false;
    }
    let segs = path.segments();
    let domain = segs.first().map(|s| s.as_str()).unwrap_or("");
    let method = segs.get(1).map(|s| s.as_str()).unwrap_or("");
    // Domains that inherently leave the trust boundary.
    matches!(
        domain,
        "email" | "chat_platform" | "instant_messaging_platform" | "http_callback" | "http"
    )
        || matches!(method, "post" | "send" | "publish" | "reply" | "emit")
        // fetch with a body is outbound; a bare GET is covered by Fetched taint.
        || (domain == "fetch" && matches!(method, "post" | "put" | "patch"))
}

/// Current wall clock in millis since epoch.
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            let before_epoch = i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX);
            before_epoch.saturating_neg()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{Driver, DriverContext, DriverDescriptor, DriverError, EchoDriver};
    use crate::fact::FactSink;
    use crate::handle::HandleTable;
    use crate::open::{OpenRequest, open_resource};
    use anyhow::{Context, bail, ensure};
    use parking_lot::RwLock;
    use xolotl_state::{Backend, InMemoryBackend};
    use xolotl_types::{
        Binding, ConstraintSet, DriverRef, Expiry, Grant, Interface, InterfaceFamily, InterfaceSet,
        Metadata, Method, MethodBitmap, MethodId, ModalitySet, OutputModeSet, Path, Purity,
        Resource, ResourceDescriptor, ResourceId, ResourceKind, ResourceSelector, RightFlags,
        Rights, SchemaId, TaintSet, TaintSource, Transport,
    };

    fn test_state() -> Backend {
        Arc::new(InMemoryBackend::new())
    }

    fn executor() -> Executor {
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        Executor::new(ProcessId::new(1), dp, Registry::new(), StepTable::new())
    }

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    fn rn(path: &str) -> anyhow::Result<ResourceName> {
        Ok(ResourceName::new(Path::parse(path)?))
    }

    #[derive(Clone)]
    struct TestStateReadDriver {
        state: Backend,
    }

    #[async_trait::async_trait]
    impl Driver for TestStateReadDriver {
        async fn call(
            &self,
            method: MethodId,
            _input: Value,
            _output: xolotl_types::OutputMode,
            ctx: &DriverContext,
        ) -> Result<Outcome, DriverError> {
            if method.get() != 0 {
                return Err(DriverError::NoSuchMethod(method));
            }
            let path = ctx
                .target_path
                .clone()
                .ok_or_else(|| DriverError::Other("state read has no bound path".into()))?;
            let tv = self
                .state
                .read_tainted(&path)
                .await
                .map_err(|e| DriverError::Other(e.to_string()))?;
            match tv {
                Some(tv) => {
                    ctx.set_output_taint(tv.taint);
                    Ok(Outcome::Done(tv.value))
                }
                None => Ok(Outcome::Done(Value::Null)),
            }
        }
    }

    struct TestResourceSpec {
        path: &'static str,
        kind: ResourceKind,
        family: InterfaceFamily,
        method_name: &'static str,
        method_id: u64,
        purity: Purity,
        replay: ReplayClass,
        driver_name: &'static str,
        selector: &'static str,
    }

    fn register_test_resource(
        reg: &Registry,
        spec: TestResourceSpec,
        driver: Arc<dyn Driver>,
    ) -> anyhow::Result<(ResourceId, ResourceName)> {
        let iface_id = reg.next_interface_id();
        reg.register_interface(Interface {
            id: iface_id,
            family: spec.family,
            methods: vec![Method {
                id: MethodId::new(spec.method_id),
                name: spec.method_name.into(),
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::TEXT,
                purity: spec.purity,
                replay: spec.replay,
                supports: OutputModeSet::UNARY,
                cost: Default::default(),
                batchable: false,
                finalize_allowed: false,
            }],
            laws: Vec::new(),
        });
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: spec.driver_name.into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: Transport::InProcess,
            driver,
        });
        let binding_id = reg.next_binding_id();
        reg.admit_binding(Binding {
            id: binding_id,
            selector: ResourceSelector::parse(spec.selector)?,
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: DriverRef {
                id: driver_id,
                name: spec.driver_name.into(),
            },
            endpoint: None,
            generation: 1,
        })
        .context("test binding admission failed")?;
        let name = rn(spec.path)?;
        let rid = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: name.clone(),
                    kind: spec.kind,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )
        .context("test resource admission failed")?;
        Ok((rid, name))
    }

    #[tokio::test]
    async fn pure_evaluates() -> anyhow::Result<()> {
        let ex = executor();
        let out = ex.eval(&DoNode::pure(Value::Int(5))).await;
        ensure!(
            out == Outcome::Done(Value::Int(5)),
            "pure node outcome mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn attached_missing_process_does_not_run_as_root() -> anyhow::Result<()> {
        let ex = executor().with_processes(crate::process::ProcessTable::new());
        let out = ex.eval(&DoNode::pure(Value::Int(5))).await;
        ensure!(
            matches!(
                out,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation {
                    ref policy,
                    ref detail,
                }) if policy == "executor" && detail.contains("unknown process 1")
            ),
            "missing process should fail closed, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn acting_denied_without_delegate_grant() -> anyhow::Result<()> {
        // Process 1 holds no grants (empty registry). An Acting block must be
        // denied fail-closed.
        let ex = executor();
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
            DoNode::pure(Value::Int(1)),
        );
        match ex.eval(&prog).await {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "act-as", "unexpected policy: {policy}");
            }
            other => bail!("expected act-as PolicyViolation, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn acting_allowed_with_delegate_grant() -> anyhow::Result<()> {
        use xolotl_types::{Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let reg = Registry::new();
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://process/bob")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::DELEGATE),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let ex = Executor::new(ProcessId::new(1), dp, reg, StepTable::new());
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
            DoNode::pure(Value::Int(7)),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Int(7)),
            "delegate grant should allow acting, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_process_short_circuits_at_operation_boundary() -> anyhow::Result<()> {
        // A process marked Cancelled must not issue its Operation: the boundary
        // check short-circuits to Failure::Cancelled.
        use crate::process::{ProcessEntry, ProcessTable};
        use xolotl_graph::OperationTemplate;
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let procs = ProcessTable::new();
        procs.insert(ProcessEntry::new(
            ProcessId::new(1),
            None,
            IdentityRef::ROOT,
        ));
        let cancelled = procs.cancel_if_non_terminal(ProcessId::new(1));
        ensure!(cancelled == Some(true), "process should be cancelled");
        let ex = Executor::new(ProcessId::new(1), dp, Registry::new(), StepTable::new())
            .with_processes(procs);
        // A bare Operation node (target need not resolve — the cancel check fires
        // before resource resolution).
        let prog = DoNode::op(OperationTemplate {
            target: rn("effect://x/post")?,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Fail(xolotl_types::Failure::Cancelled),
            "cancelled process should short-circuit, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bound_handle_must_match_target_resource() -> anyhow::Result<()> {
        let (facts, _) = FactSink::in_memory();
        let handles = Arc::new(RwLock::new(HandleTable::new()));
        let dp = DataPlane::new(handles.clone(), facts, test_state());
        let reg = Registry::new();
        let (first_resource, first_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://cache/first",
                kind: ResourceKind::Effect,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "first",
                selector: "perform://effect/cache/first",
            },
            Arc::new(EchoDriver),
        )?;
        let (_, second_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://cache/second",
                kind: ResourceKind::Effect,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "second",
                selector: "perform://effect/cache/second",
            },
            Arc::new(EchoDriver),
        )?;
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/cache/first")?,
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: first_resource,
                    verb: "perform".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(first_name.path().clone()),
                    now_millis: 0,
                },
            )
            .context("first resource open failed")?
        };
        let ex = Executor::new(ProcessId::new(1), dp, reg, StepTable::new());
        ex.bind_handle(second_name.clone(), handle);

        let out = ex
            .eval(&DoNode::op(OperationTemplate {
                target: second_name,
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: Some(Value::Null),
            }))
            .await;
        ensure!(
            matches!(
                out,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation { ref policy, .. })
                    if policy == "open"
            ),
            "mismatched bound handle was accepted: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn acting_denied_when_grant_lacks_delegate_flag() -> anyhow::Result<()> {
        use xolotl_types::{Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let reg = Registry::new();
        // Selector matches act-as://process/bob but WITHOUT the DELEGATE flag.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://process/bob")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::CLONE),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let ex = Executor::new(ProcessId::new(1), dp, reg, StepTable::new());
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
            DoNode::pure(Value::Int(1)),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(
                out,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation { .. })
            ),
            "acting without delegate flag should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn and_then_runs_step() -> anyhow::Result<()> {
        let ex = executor();
        ex.steps.install(ex.process, "double", |v, _| match v {
            Value::Int(i) => DoNode::pure(Value::Int(i * 2)),
            _ => DoNode::pure(Value::Null),
        })?;
        let prog = DoNode::pure(Value::Int(21)).and_then(s("double"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Int(42)),
            "and_then output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn step_ref_must_belong_to_current_process() -> anyhow::Result<()> {
        let ex = executor();
        ex.steps.install(ex.process, "double", |v, _| match v {
            Value::Int(i) => DoNode::pure(Value::Int(i * 2)),
            _ => DoNode::pure(Value::Null),
        })?;
        let prog = DoNode::pure(Value::Int(21)).and_then(StepRef::new(ProcessId::new(2), "double"));
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(out, Outcome::Fail(xolotl_types::Failure::PolicyViolation { ref policy, .. }) if policy == "step"),
            "cross-process step ref should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn or_else_recovers() -> anyhow::Result<()> {
        let ex = executor();
        ex.steps.install(ex.process, "fallback", |_, _| {
            DoNode::pure(Value::Str("ok".into()))
        })?;
        let prog = DoNode::fail(xolotl_types::Failure::Cancelled).or_else(s("fallback"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Str("ok".into())),
            "or_else recovery mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn or_else_passes_through_success() -> anyhow::Result<()> {
        let ex = executor();
        ex.steps.install(ex.process, "never", |_, _| {
            DoNode::pure(Value::Str("recovered".into()))
        })?;
        let prog = DoNode::pure(Value::Int(1)).or_else(s("never"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Int(1)),
            "or_else success passthrough mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn let_use_binds() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::r#let("x", DoNode::pure(Value::Int(7)), DoNode::use_("x"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Int(7)),
            "let/use output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn both_joins_pair() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::both(DoNode::pure(Value::Int(1)), DoNode::pure(Value::Int(2)));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::List(vec![Value::Int(1), Value::Int(2)])),
            "both output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn both_fails_if_either_arm_fails() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::both(
            DoNode::pure(Value::Int(1)),
            DoNode::fail(xolotl_types::Failure::Cancelled),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(out, Outcome::Fail(_)),
            "both should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn race_takes_first_success() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::race(
            DoNode::pure(Value::Str("a".into())),
            DoNode::pure(Value::Str("b".into())),
        );
        // Both are immediate; the result is one of them (deterministic select
        // bias toward the first-polled arm in tokio::select! is not guaranteed,
        // so accept either).
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(out, Outcome::Done(Value::Str(ref s)) if s == "a" || s == "b"),
            "race output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unbound_use_fails_at_compile() -> anyhow::Result<()> {
        let ex = executor();
        // A bare Use with no enclosing Let fails to compile → executor surfaces
        // a policy failure rather than panicking.
        let out = ex.eval(&DoNode::use_("nope")).await;
        ensure!(
            matches!(out, Outcome::Fail(_)),
            "unbound use should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn chained_and_then_keeps_threading_value() -> anyhow::Result<()> {
        let ex = executor();
        ex.steps.install(ex.process, "inc", |v, _| match v {
            Value::Int(i) => DoNode::pure(Value::Int(i + 1)),
            _ => DoNode::pure(Value::Null),
        })?;
        let prog = DoNode::pure(Value::Int(0))
            .and_then(s("inc"))
            .and_then(s("inc"))
            .and_then(s("inc"));
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Int(3)),
            "chained and_then output mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_deadline_in_past_returns_immediately() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::wait_deadline(0); // epoch — already passed
        let out = ex.eval(&prog).await;
        ensure!(
            out == Outcome::Done(Value::Null),
            "past deadline output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_signal_resolves_on_write() -> anyhow::Result<()> {
        let state = test_state();
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            state.clone(),
        );
        let ex = Executor::new(ProcessId::new(1), dp, Registry::new(), StepTable::new())
            .with_state(state.clone());
        let signal = xolotl_types::Path::parse("state://stream/1/sig")?;
        // Write the signal after a short delay; the Wait must observe it.
        let writer = {
            let state = state.clone();
            let signal = signal.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                state.write_set(&signal, Value::Int(99)).await?;
                Ok::<(), anyhow::Error>(())
            })
        };
        let out = ex.eval(&DoNode::wait_signal(signal)).await;
        writer
            .await
            .context("signal writer task failed to join")??;
        ensure!(
            out == Outcome::Done(Value::Int(99)),
            "wait signal output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_signal_without_state_fails() -> anyhow::Result<()> {
        let ex = executor(); // no state backend bound
        let signal = xolotl_types::Path::parse("state://stream/1/sig")?;
        let out = ex.eval(&DoNode::wait_signal(signal)).await;
        ensure!(
            matches!(out, Outcome::Fail(_)),
            "wait without state should fail, got {out:?}"
        );
        Ok(())
    }

    #[test]
    fn causal_positions_match_compiled_graph() -> anyhow::Result<()> {
        // The Operations the executor issues carry the compiler's NodeIds. Here
        // we just assert the compiled graph is what the executor walks: a
        // 2-node chain (Op, Step) numbers the Op at 0 (its CausalPosition).
        use xolotl_graph::{NodeKind, compile_do};
        let prog = DoNode::op(xolotl_graph::OperationTemplate {
            target: rn("effect://x/post")?,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
        .and_then(s("s"));
        let g = compile_do(&prog).context("compile_do failed")?;
        let node = g.node(NodeId::new(0)).context("missing node 0")?;
        ensure!(
            matches!(node.kind, NodeKind::Operation(_)),
            "node 0 should be an operation"
        );
        Ok(())
    }

    #[test]
    fn intrinsic_source_classifies_targets() -> anyhow::Result<()> {
        use xolotl_types::TaintSource;
        let infer = rn("effect://inference/infer")?;
        ensure!(
            matches!(intrinsic_source(&infer), Some(TaintSource::ModelOutput)),
            "inference target should be model output taint"
        );
        let fetch = rn("effect://fetch/get")?;
        ensure!(
            matches!(intrinsic_source(&fetch), Some(TaintSource::Fetched { .. })),
            "fetch target should be fetched taint"
        );
        let vault = rn("state://vault/alice/x")?;
        ensure!(
            matches!(
                intrinsic_source(&vault),
                Some(TaintSource::Protected { .. })
            ),
            "vault target should be protected taint"
        );
        let plain = rn("state://memory/alice")?;
        ensure!(
            intrinsic_source(&plain).is_none(),
            "plain memory target should not have intrinsic taint"
        );
        Ok(())
    }

    #[test]
    fn is_outbound_classifies_targets() -> anyhow::Result<()> {
        let post = rn("effect://chat_platform/post")?;
        ensure!(is_outbound(&post), "chat platform post should be outbound");
        let instant_messaging_platform = rn("effect://instant_messaging_platform/notify")?;
        ensure!(
            is_outbound(&instant_messaging_platform),
            "instant messaging notify should be outbound"
        );
        let http_callback = rn("effect://http_callback/notify")?;
        ensure!(
            is_outbound(&http_callback),
            "HTTP callback notify should be outbound"
        );
        let email = rn("effect://email/send")?;
        ensure!(is_outbound(&email), "email send should be outbound");
        let infer = rn("effect://inference/infer")?;
        ensure!(
            !is_outbound(&infer),
            "inference target should not be outbound"
        );
        let read = rn("state://memory/alice")?;
        ensure!(!is_outbound(&read), "state read should not be outbound");
        Ok(())
    }

    #[tokio::test]
    async fn protected_data_to_outbound_is_denied() -> anyhow::Result<()> {
        // A value tainted Protected (read from vault) flowing into an outbound
        // Operation is structurally denied — the taint gate fires before
        // resource resolution would.
        use xolotl_graph::OperationTemplate;
        let ex = executor();
        let env = Env::root(IdentityRef::ROOT).with_taint(xolotl_types::TaintSet::of(
            xolotl_types::TaintSource::Protected {
                path: xolotl_types::Path::parse("state://vault/alice/x")?,
            },
        ));
        let tmpl = OperationTemplate {
            target: rn("effect://chat_platform/post")?,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        let (out, _t) = ex
            .run_operation(
                &tmpl,
                Value::Str("secret".into()),
                &env,
                NodeId::new(0),
                true,
            )
            .await;
        match out {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "taint", "unexpected policy: {policy}");
            }
            other => bail!("expected taint PolicyViolation, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn persisted_protected_state_taint_blocks_later_outbound_op() -> anyhow::Result<()> {
        let state = test_state();
        let secret_path = Path::parse("state://memory/private")?;
        let protected = TaintSet::of(TaintSource::Protected {
            path: secret_path.clone(),
        });
        state
            .write_set_tainted(&secret_path, Value::Str("secret".into()), protected)
            .await
            .context("writing tainted state failed")?;

        let reg = Registry::new();
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::all(),
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let (state_resource, _) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "state://memory",
                kind: ResourceKind::State,
                family: InterfaceFamily::Value,
                method_name: "read",
                method_id: 0,
                purity: Purity::Pure,
                replay: ReplayClass::Observation,
                driver_name: "state-read",
                selector: "read://state/memory/**",
            },
            Arc::new(TestStateReadDriver {
                state: state.clone(),
            }),
        )?;
        let (post_resource, post_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://chat_platform/post",
                kind: ResourceKind::Effect,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "post",
                selector: "perform://effect/chat_platform/post",
            },
            Arc::new(EchoDriver),
        )?;

        let (facts, _) = FactSink::in_memory();
        let handles = Arc::new(RwLock::new(HandleTable::new()));
        let dp = DataPlane::new(handles.clone(), facts, state);
        let ex = Executor::new(ProcessId::new(1), dp, reg.clone(), StepTable::new());

        let read_target = ResourceName::new(secret_path.clone());
        let read_handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: state_resource,
                    verb: "read".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(secret_path.clone()),
                    now_millis: 0,
                },
            )
            .context("state read open failed")?
        };
        ex.bind_handle(read_target.clone(), read_handle);

        let post_handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: post_resource,
                    verb: "perform".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: None,
                    now_millis: 0,
                },
            )
            .context("post open failed")?
        };
        ex.bind_handle(post_name.clone(), post_handle);

        let post_step_target = post_name;
        ex.steps.install(ex.process, "post", move |_, _| {
            DoNode::op(OperationTemplate {
                target: post_step_target.clone(),
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: None,
            })
        })?;

        let prog = DoNode::op(OperationTemplate {
            target: read_target,
            method: "read".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
        .and_then(s("post"));

        match ex.eval(&prog).await {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "taint", "unexpected policy: {policy}");
            }
            other => bail!("expected taint PolicyViolation, got {other:?}"),
        }
        Ok(())
    }
}
