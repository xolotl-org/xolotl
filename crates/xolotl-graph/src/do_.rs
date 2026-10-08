//! `Do<A>` — the native graph program front-end.
//!
//! `Do<A>` is a computation AST that **compiles into** an
//! [`ExecutionGraph`](crate::graph::ExecutionGraph). The Executor runs the
//! compiled graph, see [`crate::compile`]. Explicit control flow makes
//! composition inspectable and keeps host-bound continuations named.
//!
//! Combinators have fixed graph-compilation rules. Steps
//! are **named, pure** `Value -> Do<A>` continuations. Named continuations are
//! serializable and avoid cross-identity code injection.

use crate::graph::{OperationTemplate, StepRef, WaitSpec};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use xolotl_types::{CapError, Capability, Failure, Path, PathError, ProcessId, Value};

/// The nine combinators plus an `Op` leaf and a `Wait` leaf. Erased
/// over the `A` type parameter — the kernel validates the Outcome shape at the
/// boundary, the AST itself flows as data.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoNode {
    /// `Pure :: A -> Do<A>` — lift a value.
    Pure(#[serde(with = "xolotl_types::tagged_value")] Value),
    /// `AndThen :: Do<A> -> (A -> Do<B>) -> Do<B>` — sequence into a step.
    AndThen {
        /// Program whose successful result feeds the continuation.
        d: Box<DoNode>,
        /// Named pure continuation to invoke with `d`'s result.
        then: StepRef,
    },
    /// On failure of `d`, run `or` with the failure as input.
    OrElse {
        /// Program guarded by this recovery path.
        d: Box<DoNode>,
        /// Named recovery step invoked with the failure value.
        or: StepRef,
    },
    /// Run cleanup after the body succeeds, fails, or is cooperatively cancelled.
    /// Cleanup receives the body's original input; the body's result is preserved
    /// unless cleanup fails after a successful body.
    Finally {
        /// Guarded program.
        body: Box<DoNode>,
        /// Cleanup program.
        cleanup: Box<DoNode>,
    },
    /// Run both; result is the pair.
    Both(Box<DoNode>, Box<DoNode>),
    /// Run both; first to complete wins, the other is cancelled.
    Race(Box<DoNode>, Box<DoNode>),
    /// Bind the result of `value` to `name`, available in `body` as `Use(name)`.
    Let {
        /// Binding name visible while compiling `body`.
        name: String,
        /// Program that produces the bound value.
        value: Box<DoNode>,
        /// Program compiled with `name` in scope.
        body: Box<DoNode>,
    },
    /// Reference a `Let`-bound name.
    Use(String),
    /// Run `body` under a block-level identity.
    Acting {
        /// Identity path to act as for operations inside `body`.
        identity: Path,
        /// Program executed within the acting scope.
        body: Box<DoNode>,
    },
    /// Inject a failure (propagates to the nearest enclosing `Branch`).
    Fail(Failure),
    /// Block until a signal path is written or a wall-clock deadline.
    Wait(WaitSpec),
    /// The side-effecting leaf: issue one Operation.
    Op(OperationTemplate),
}

impl Clone for DoNode {
    /// Clone native control flow with an explicit work stack. Payload cloning
    /// retains the contracts of Value, Failure, and the operation/step types.
    fn clone(&self) -> Self {
        let empty = || Box::new(Self::wait_deadline(0));
        let mut cloned = Self::wait_deadline(0);
        let mut pending = alloc::vec![(self, &mut cloned)];
        while let Some((source, destination)) = pending.pop() {
            *destination = match source {
                Self::Pure(value) => Self::Pure(value.clone()),
                Self::Fail(failure) => Self::Fail(failure.clone()),
                Self::Op(operation) => Self::Op(operation.clone()),
                Self::Wait(spec) => Self::Wait(spec.clone()),
                Self::Use(name) => Self::Use(name.clone()),
                Self::AndThen { then, .. } => Self::AndThen {
                    d: empty(),
                    then: then.clone(),
                },
                Self::OrElse { or, .. } => Self::OrElse {
                    d: empty(),
                    or: or.clone(),
                },
                Self::Acting { identity, .. } => Self::Acting {
                    identity: identity.clone(),
                    body: empty(),
                },
                Self::Finally { .. } => Self::Finally {
                    body: empty(),
                    cleanup: empty(),
                },
                Self::Let { name, .. } => Self::Let {
                    name: name.clone(),
                    value: empty(),
                    body: empty(),
                },
                Self::Both(..) => Self::Both(empty(), empty()),
                Self::Race(..) => Self::Race(empty(), empty()),
            };
            match (source, destination) {
                (Self::AndThen { d: source, .. }, Self::AndThen { d: destination, .. })
                | (Self::OrElse { d: source, .. }, Self::OrElse { d: destination, .. })
                | (
                    Self::Acting { body: source, .. },
                    Self::Acting {
                        body: destination, ..
                    },
                ) => {
                    pending.push((source.as_ref(), destination.as_mut()));
                }
                (
                    Self::Finally {
                        body: left,
                        cleanup: right,
                    },
                    Self::Finally {
                        body: cloned_left,
                        cleanup: cloned_right,
                    },
                )
                | (
                    Self::Let {
                        value: left,
                        body: right,
                        ..
                    },
                    Self::Let {
                        value: cloned_left,
                        body: cloned_right,
                        ..
                    },
                )
                | (Self::Both(left, right), Self::Both(cloned_left, cloned_right))
                | (Self::Race(left, right), Self::Race(cloned_left, cloned_right)) => {
                    pending.push((right.as_ref(), cloned_right.as_mut()));
                    pending.push((left.as_ref(), cloned_left.as_mut()));
                }
                _ => {}
            }
        }
        cloned
    }
}

impl crate::source_release::SourceTree for DoNode {
    fn has_children(&self) -> bool {
        match self {
            Self::AndThen { .. }
            | Self::OrElse { .. }
            | Self::Finally { .. }
            | Self::Both(..)
            | Self::Race(..)
            | Self::Let { .. }
            | Self::Acting { .. } => true,
            Self::Pure(_) | Self::Use(_) | Self::Fail(_) | Self::Wait(_) | Self::Op(_) => false,
        }
    }

    fn empty() -> Self {
        Self::Wait(WaitSpec::Deadline(0))
    }

    fn detach_children(&mut self, pending: &mut Vec<Self>) {
        use crate::source_release::detach;
        match self {
            Self::AndThen { d, .. } | Self::OrElse { d, .. } | Self::Acting { body: d, .. } => {
                detach(d.as_mut(), pending)
            }
            Self::Finally { body, cleanup } => {
                detach(body.as_mut(), pending);
                detach(cleanup.as_mut(), pending);
            }
            Self::Let { value, body, .. } => {
                detach(value.as_mut(), pending);
                detach(body.as_mut(), pending);
            }
            Self::Both(left, right) | Self::Race(left, right) => {
                detach(left.as_mut(), pending);
                detach(right.as_mut(), pending);
            }
            Self::Pure(_) | Self::Use(_) | Self::Fail(_) | Self::Wait(_) | Self::Op(_) => {}
        }
    }
}

impl Drop for DoNode {
    fn drop(&mut self) {
        crate::source_release::release(self);
    }
}

impl DoNode {
    /// Construct a [`DoNode::Pure`] value.
    pub fn pure<V: Into<Value>>(v: V) -> Self {
        DoNode::Pure(v.into())
    }

    /// Construct a side-effecting [`DoNode::Op`] leaf.
    pub fn op(tmpl: OperationTemplate) -> Self {
        DoNode::Op(tmpl)
    }

    /// Construct a [`DoNode::Fail`] leaf.
    pub fn fail(f: Failure) -> Self {
        DoNode::Fail(f)
    }

    /// Sequence this program into a named pure step.
    pub fn and_then(self, then: StepRef) -> Self {
        DoNode::AndThen {
            d: Box::new(self),
            then,
        }
    }
    /// `map`: project the result through a **pure** Step. `map<B>`
    /// desugars to `AndThen` into a pure projecting Step — it is a named alias
    /// of [`and_then`](Self::and_then) whose contract is that `step` performs
    /// no effects (it returns `Pure(f(value))`). Use this for value reshaping;
    /// use `and_then` when the continuation may itself issue Operations.
    pub fn map(self, step: StepRef) -> Self {
        self.and_then(step)
    }

    /// Recover from this program's failure with a named step.
    pub fn or_else(self, or: StepRef) -> Self {
        DoNode::OrElse {
            d: Box::new(self),
            or,
        }
    }

    /// Run `cleanup` on every cooperative exit from this program.
    pub fn finally(self, cleanup: DoNode) -> Self {
        DoNode::Finally {
            body: Box::new(self),
            cleanup: Box::new(cleanup),
        }
    }

    /// Run two programs to completion and join their results.
    pub fn both(a: DoNode, b: DoNode) -> Self {
        DoNode::Both(Box::new(a), Box::new(b))
    }

    /// Run two programs and keep the first completed result.
    pub fn race(a: DoNode, b: DoNode) -> Self {
        DoNode::Race(Box::new(a), Box::new(b))
    }

    /// Bind `name` to `value` while compiling `body`.
    pub fn r#let(name: impl Into<String>, value: DoNode, body: DoNode) -> Self {
        DoNode::Let {
            name: name.into(),
            value: Box::new(value),
            body: Box::new(body),
        }
    }

    /// Reference a value bound by an enclosing [`DoNode::Let`].
    pub fn use_(name: impl Into<String>) -> Self {
        DoNode::Use(name.into())
    }

    /// Run `body` under a block-level acting identity.
    pub fn acting(identity: Path, body: DoNode) -> Self {
        DoNode::Acting {
            identity,
            body: Box::new(body),
        }
    }

    /// Wait until `path` is written.
    pub fn wait_signal(path: Path) -> Self {
        DoNode::Wait(WaitSpec::Signal(path))
    }
    /// Wait until a wall-clock deadline (millis since epoch).
    pub fn wait_deadline(at_millis: i64) -> Self {
        DoNode::Wait(WaitSpec::Deadline(at_millis))
    }

    /// Acquire a value, pass it to `body_step`, then pass the acquired value
    /// to `release_step` on every cooperative exit. The body result is retained.
    pub fn bracket(acquire: DoNode, body_step: StepRef, release_step: StepRef) -> Self {
        let resource = "__bracket_resource";
        DoNode::r#let(
            resource,
            acquire,
            DoNode::use_(resource)
                .and_then(body_step)
                .finally(DoNode::use_(resource).and_then(release_step)),
        )
    }

    /// Bounded `retry`: desugars to a chain of [`OrElse`](DoNode::OrElse) so
    /// that each failure routes to `recover`, which is expected to re-attempt
    /// the work.
    ///
    /// Because Steps are **named, pure continuations** (never closures) and the
    /// AST has no loop node, the bound is encoded *structurally*: we nest
    /// `OrElse` `max` times, giving up to `max` additional attempts after the
    /// initial run (so `max + 1` total tries). With `max == 0` the program is
    /// returned unchanged (no retry). The retry count is represented by the
    /// fixed nesting depth here: fully serializable, with no runtime loop.
    ///
    /// ```text
    /// retry(d, 2, recover)
    ///   = OrElse { d: OrElse { d: d, or: recover }, or: recover }
    /// ```
    pub fn retry(self, max: u32, recover: StepRef) -> Self {
        let mut node = self;
        for _ in 0..max {
            node = node.or_else(recover.clone());
        }
        node
    }

    /// Number of AST nodes (budget / complexity heuristic).
    pub fn size(&self) -> usize {
        let mut count = 0;
        let mut pending = alloc::vec![self];
        while let Some(node) = pending.pop() {
            count += 1;
            match node {
                DoNode::AndThen { d, .. }
                | DoNode::OrElse { d, .. }
                | DoNode::Acting { body: d, .. } => pending.push(d),
                DoNode::Finally { body, cleanup } => {
                    pending.push(cleanup);
                    pending.push(body);
                }
                DoNode::Let { value, body, .. } => {
                    pending.push(body);
                    pending.push(value);
                }
                DoNode::Both(a, b) | DoNode::Race(a, b) => {
                    pending.push(b);
                    pending.push(a);
                }
                DoNode::Pure(_)
                | DoNode::Use(_)
                | DoNode::Fail(_)
                | DoNode::Wait(_)
                | DoNode::Op(_) => {}
            }
        }
        count
    }

    /// Whether any branch exceeds `max` nested nodes, counting the root as one.
    /// Uses an explicit work stack so admission itself handles deep input.
    pub fn exceeds_depth(&self, max: usize) -> bool {
        if max == 0 {
            return true;
        }
        if !crate::source_release::SourceTree::has_children(self) {
            return false;
        }
        let mut pending = alloc::vec![(self, 1usize)];
        while let Some((node, depth)) = pending.pop() {
            if depth > max {
                return true;
            }
            let child_depth = depth + 1;
            match node {
                DoNode::AndThen { d, .. }
                | DoNode::OrElse { d, .. }
                | DoNode::Acting { body: d, .. } => pending.push((d, child_depth)),
                DoNode::Finally { body, cleanup } => {
                    pending.push((cleanup, child_depth));
                    pending.push((body, child_depth));
                }
                DoNode::Let { value, body, .. } => {
                    pending.push((body, child_depth));
                    pending.push((value, child_depth));
                }
                DoNode::Both(a, b) | DoNode::Race(a, b) => {
                    pending.push((b, child_depth));
                    pending.push((a, child_depth));
                }
                DoNode::Pure(_)
                | DoNode::Use(_)
                | DoNode::Fail(_)
                | DoNode::Wait(_)
                | DoNode::Op(_) => {}
            }
        }
        false
    }

    /// Walk every `Op` leaf in evaluation order (linters / tests).
    pub fn ops(&self) -> Vec<&OperationTemplate> {
        let mut out = Vec::new();
        let mut pending = alloc::vec![self];
        while let Some(node) = pending.pop() {
            match node {
                DoNode::Op(template) => out.push(template),
                DoNode::AndThen { d, .. }
                | DoNode::OrElse { d, .. }
                | DoNode::Acting { body: d, .. } => pending.push(d),
                DoNode::Finally { body, cleanup } => {
                    pending.push(cleanup);
                    pending.push(body);
                }
                DoNode::Let { value, body, .. } => {
                    pending.push(body);
                    pending.push(value);
                }
                DoNode::Both(a, b) | DoNode::Race(a, b) => {
                    pending.push(b);
                    pending.push(a);
                }
                DoNode::Pure(_) | DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) => {}
            }
        }
        out
    }

    /// Bind structured `state://process/self/...` operation and signal paths.
    ///
    /// Consumes the program and updates paths in place. Literal values, step
    /// names and arguments are unchanged, and their payloads are not cloned.
    pub fn bind_process_local_refs(mut self, process: ProcessId) -> Result<Self, PathError> {
        self.bind_process_paths(process)?;
        Ok(self)
    }

    fn bind_process_paths(&mut self, process: ProcessId) -> Result<(), PathError> {
        let mut pending = alloc::vec![self];
        while let Some(node) = pending.pop() {
            match node {
                DoNode::AndThen { d, .. }
                | DoNode::OrElse { d, .. }
                | DoNode::Acting { body: d, .. } => pending.push(d),
                DoNode::Finally { body, cleanup } => {
                    pending.push(cleanup);
                    pending.push(body);
                }
                DoNode::Both(left, right) | DoNode::Race(left, right) => {
                    pending.push(right);
                    pending.push(left);
                }
                DoNode::Let { value, body, .. } => {
                    pending.push(body);
                    pending.push(value);
                }
                DoNode::Wait(WaitSpec::Signal(path)) => {
                    bind_process_self_path_in_place(path, process)?;
                }
                DoNode::Op(template) => {
                    bind_process_self_path_in_place(&mut template.target.0, process)?;
                }
                DoNode::Pure(_)
                | DoNode::Use(_)
                | DoNode::Fail(_)
                | DoNode::Wait(WaitSpec::Deadline(_)) => {}
            }
        }
        Ok(())
    }
}

fn bind_process_self_path_in_place(path: &mut Path, process: ProcessId) -> Result<(), PathError> {
    let segments = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segments.first().map(|segment| segment.as_str()) != Some("process")
        || segments.get(1).map(|segment| segment.as_str()) != Some("self")
    {
        return Ok(());
    }
    let mut bound = Path::try_new("state")?
        .try_push("process")?
        .try_push(process.get().to_string())?;
    for segment in &segments[2..] {
        bound = bound.try_push(segment.as_str())?;
    }
    *path = bound;
    Ok(())
}

pub(crate) fn bind_process_self_capability_literal(
    literal: &str,
    process: ProcessId,
) -> Result<String, CapError> {
    let mut capability = Capability::parse(literal)?;
    if bind_process_self_capability(&mut capability, process) {
        Ok(capability.to_string())
    } else {
        Ok(literal.to_string())
    }
}

/// Bind a structured `state/process/self/...` capability to a concrete process.
/// Returns whether a segment changed. Verbs, predicates and remaining segments
/// are preserved; hosts must check the bound capability against the parent's grants.
pub fn bind_process_self_capability(capability: &mut Capability, process: ProcessId) -> bool {
    let changed = capability.scheme == "state"
        && capability
            .segments
            .first()
            .is_some_and(|segment| segment.as_str() == "process")
        && capability
            .segments
            .get(1)
            .is_some_and(|segment| segment.as_str() == "self");
    if changed {
        capability.segments[1] = process.get().to_string().into();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, anyhow, bail, ensure};
    use xolotl_types::{ProcessId, ResourceName};

    fn s(name: &str) -> StepRef {
        StepRef::new(name)
    }

    fn op(path: &str) -> anyhow::Result<OperationTemplate> {
        Ok(OperationTemplate {
            target: ResourceName::new(
                Path::parse(path)
                    .map_err(|error| anyhow!("path parse failed for {path}: {error}"))?,
            ),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
    }

    #[test]
    fn build_and_then_chain() -> anyhow::Result<()> {
        let d = DoNode::op(op("effect://x/post")?).and_then(s("handle"));
        ensure!(
            matches!(d, DoNode::AndThen { .. }),
            "unexpected node: {d:?}"
        );
        Ok(())
    }

    #[test]
    fn map_builds_and_then() -> anyhow::Result<()> {
        let d = DoNode::op(op("effect://x/post")?).map(s("project"));
        match &d {
            DoNode::AndThen { then, .. } => {
                ensure!(then.name == "project", "unexpected step: {:?}", then.name);
            }
            other => bail!("map must desugar to AndThen, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn retry_zero_is_identity() -> anyhow::Result<()> {
        let d = DoNode::op(op("effect://x")?).retry(0, s("again"));
        ensure!(matches!(d, DoNode::Op(_)), "unexpected node: {d:?}");
        Ok(())
    }

    #[test]
    fn retry_nests_or_else() -> anyhow::Result<()> {
        let d = DoNode::op(op("effect://x")?).retry(2, s("again"));
        match &d {
            DoNode::OrElse { d: outer_d, or } => {
                ensure!(or.name == "again", "unexpected outer step: {:?}", or.name);
                match outer_d.as_ref() {
                    DoNode::OrElse { d: inner_d, or } => {
                        ensure!(or.name == "again", "unexpected inner step: {:?}", or.name);
                        ensure!(
                            matches!(inner_d.as_ref(), DoNode::Op(_)),
                            "unexpected retry body: {inner_d:?}"
                        );
                    }
                    other => bail!("expected nested OrElse, got {other:?}"),
                }
            }
            other => bail!("expected OrElse, got {other:?}"),
        }
        let d2 = DoNode::op(op("effect://x")?).retry(2, s("again"));
        ensure!(d2.size() == 3, "unexpected retry size: {}", d2.size());
        Ok(())
    }

    #[test]
    fn collect_ops_walks_all_branches() -> anyhow::Result<()> {
        let d = DoNode::Let {
            name: "x".into(),
            value: Box::new(DoNode::op(op("effect://a")?)),
            body: Box::new(DoNode::Both(
                Box::new(DoNode::op(op("effect://b")?)),
                Box::new(DoNode::op(op("effect://c")?)),
            )),
        };
        ensure!(d.ops().len() == 3, "unexpected op count: {}", d.ops().len());
        ensure!(d.size() == 5, "unexpected size: {}", d.size());
        Ok(())
    }

    #[test]
    fn serde_roundtrip() -> anyhow::Result<()> {
        let d = DoNode::r#let("x", DoNode::pure(Value::integer(1)), DoNode::use_("x"));
        let s = serde_json::to_string(&d)?;
        let back: DoNode = serde_json::from_str(&s)?;
        ensure!(d == back, "round trip changed node: {back:?}");
        Ok(())
    }

    #[test]
    fn clone_preserves_all_native_variants_on_small_stack() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut program = DoNode::pure(Value::bytes(vec![0, 255]));
                for index in 0..2000 {
                    program = match index % 7 {
                        0 => program.and_then(s("next").with_arg(Value::null())),
                        1 => program.or_else(s("recover").with_arg(Value::integer(index))),
                        2 => program.finally(DoNode::fail(Failure::Cancelled)),
                        3 => DoNode::both(program, DoNode::op(op("effect://clone/invoke")?)),
                        4 => DoNode::race(DoNode::wait_deadline(index), program),
                        5 => DoNode::r#let(
                            "local",
                            DoNode::pure(index),
                            DoNode::both(program, DoNode::use_("local")),
                        ),
                        _ => DoNode::acting(Path::parse("identity://clone/inner")?, program),
                    };
                }
                let cloned = program.clone();
                ensure!(cloned.size() == program.size());
                ensure!(
                    crate::compile_do(&cloned)?.graph_hash
                        == crate::compile_do(&program)?.graph_hash
                );
                Ok::<_, anyhow::Error>(())
            })?
            .join()
            .map_err(|_panic| anyhow::anyhow!("small-stack clone panicked"))??;
        Ok(())
    }

    #[test]
    fn serialized_programs_preserve_literal_types_and_optional_nulls() -> anyhow::Result<()> {
        let value = Value::list(vec![
            Value::bytes(vec![0, 255]),
            Value::float(xolotl_types::FloatBits(f64::from_bits(
                0xfff8_0000_0000_0123,
            ))),
            Value::stream_end(xolotl_types::StreamMarker::Done),
        ]);
        for literal in [None, Some(Value::null()), Some(value.clone())] {
            let mut operation = op("effect://codec/invoke")?;
            operation.literal_input = literal.clone();
            let mut step = s("codec/step");
            step.arg = literal;
            let program =
                DoNode::both(DoNode::pure(value.clone()), DoNode::op(operation)).and_then(step);
            let encoded = serde_json::to_vec(&program)?;
            ensure!(serde_json::from_slice::<DoNode>(&encoded)? == program);
            let graph = crate::compile_do(&program)?;
            let encoded = serde_json::to_vec(&graph)?;
            ensure!(serde_json::from_slice::<crate::ExecutionGraph>(&encoded)? == graph);
        }
        Ok(())
    }

    #[test]
    fn bind_process_local_refs_rewrites_structured_paths_only() -> anyhow::Result<()> {
        let process = ProcessId::new(42);
        let d = DoNode::Both(
            Box::new(DoNode::op(op("state://process/self/scratch")?)),
            Box::new(DoNode::wait_signal(Path::parse(
                "state://process/self/signal",
            )?)),
        );
        let bound = d.bind_process_local_refs(process)?;
        let ops = bound.ops();
        let target = ops.first().context("missing op")?.target.path().to_string();
        ensure!(
            target == "state://process/42/scratch",
            "unexpected bound op target: {target}"
        );
        match &bound {
            DoNode::Both(_, right) => match right.as_ref() {
                DoNode::Wait(WaitSpec::Signal(path)) => {
                    ensure!(
                        path.to_string() == "state://process/42/signal",
                        "unexpected bound wait path: {path}"
                    );
                }
                other => bail!("unexpected right node: {other:?}"),
            },
            other => bail!("unexpected bound node: {other:?}"),
        }

        let value = DoNode::pure(Value::string("state://process/self/not-a-path".into()));
        ensure!(
            value.clone().bind_process_local_refs(process)? == value,
            "plain string value should not be rebound"
        );
        Ok(())
    }

    #[test]
    fn binding_process_paths_keeps_payload_and_ast_allocations() -> anyhow::Result<()> {
        let literal = vec![0x5a; 65_536];
        let argument = vec![0x7f; 65_536];
        let literal_ptr = literal.as_ptr();
        let argument_ptr = argument.as_ptr();
        let mut operation = op("state://process/self/scratch")?;
        operation.literal_input = Some(Value::bytes(literal));
        let body = Box::new(DoNode::op(operation));
        let body_ptr = std::ptr::from_ref(body.as_ref());
        let node = DoNode::AndThen {
            d: body,
            then: StepRef::new("finish").with_arg(Value::bytes(argument)),
        };
        let bound = node.bind_process_local_refs(ProcessId::new(42))?;
        let DoNode::AndThen { d, then } = &bound else {
            bail!("binding changed the program shape");
        };
        ensure!(std::ptr::from_ref(d.as_ref()) == body_ptr);
        let DoNode::Op(operation) = d.as_ref() else {
            bail!("binding changed the operation");
        };
        ensure!(operation.target.path().to_string() == "state://process/42/scratch");
        let Some(literal) = operation.literal_input.as_ref().and_then(Value::as_bytes) else {
            bail!("binding changed the literal");
        };
        let Some(argument) = then.arg.as_ref().and_then(Value::as_bytes) else {
            bail!("binding changed the argument");
        };
        ensure!(literal.as_ptr() == literal_ptr);
        ensure!(argument.as_ptr() == argument_ptr);
        ensure!(then.name == "finish");
        Ok(())
    }

    #[test]
    fn fail_is_terminal() -> anyhow::Result<()> {
        let d = DoNode::fail(Failure::Cancelled);
        ensure!(d.size() == 1, "unexpected size: {}", d.size());
        ensure!(d.ops().is_empty(), "fail node should not contain ops");
        Ok(())
    }
}
