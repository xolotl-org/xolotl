//! `Do<A>` — the preferred, serializable Program front-end.
//!
//! `Do<A>` is a computation AST that **compiles into** an
//! [`ExecutionGraph`](crate::graph::ExecutionGraph). The Executor runs the
//! compiled graph, see [`crate::compile`]. `Do<A>` exists because async call
//! stacks are unserializable, unrecoverable, and unfit for model-generated
//! plans.
//!
//! Nine combinators, each with a fixed graph-compilation rule. Steps
//! are **named, pure** `Value -> Do<A>` continuations. Named continuations are
//! serializable and avoid cross-identity code injection.

use crate::graph::{OperationTemplate, StepRef, WaitSpec};
use serde::{Deserialize, Serialize};
use xolotl_types::{
    CapError, Capability, Failure, Path, PathError, PredOp, Predicate, ProcessId, ResourceName,
    Value,
};

/// The nine combinators plus an `Op` leaf and a `Wait` leaf. Erased
/// over the `A` type parameter — the kernel validates the Outcome shape at the
/// boundary, the AST itself flows as data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoNode {
    /// `Pure :: A -> Do<A>` — lift a value.
    Pure(Value),
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

    /// Bracket pattern: acquire → use → release-on-any-exit. `release`
    /// runs whether `body_step` succeeds or fails, like try-finally.
    pub fn bracket(acquire: DoNode, body_step: StepRef, release_step: StepRef) -> Self {
        DoNode::Let {
            name: "__bracket_resource".into(),
            value: Box::new(acquire),
            body: Box::new(DoNode::OrElse {
                d: Box::new(
                    DoNode::Use("__bracket_resource".into())
                        .and_then(body_step)
                        .and_then(release_step.clone()),
                ),
                or: release_step,
            }),
        }
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
        match self {
            DoNode::Pure(_)
            | DoNode::Use(_)
            | DoNode::Fail(_)
            | DoNode::Wait(_)
            | DoNode::Op(_) => 1,
            DoNode::AndThen { d, .. }
            | DoNode::OrElse { d, .. }
            | DoNode::Acting { body: d, .. } => 1 + d.size(),
            DoNode::Let { value, body, .. } => 1 + value.size() + body.size(),
            DoNode::Both(a, b) | DoNode::Race(a, b) => 1 + a.size() + b.size(),
        }
    }

    /// Walk every `Op` leaf in evaluation order (linters / tests).
    pub fn ops(&self) -> Vec<&OperationTemplate> {
        let mut out = Vec::new();
        self.collect_ops(&mut out);
        out
    }

    /// Return a copy with process-local references bound to `process`.
    pub fn bind_process_local_refs(&self, process: ProcessId) -> Result<Self, PathError> {
        match self {
            DoNode::Pure(value) => Ok(DoNode::Pure(value.clone())),
            DoNode::AndThen { d, then } => Ok(DoNode::AndThen {
                d: Box::new(d.bind_process_local_refs(process)?),
                then: bind_step_ref(then, process),
            }),
            DoNode::OrElse { d, or } => Ok(DoNode::OrElse {
                d: Box::new(d.bind_process_local_refs(process)?),
                or: bind_step_ref(or, process),
            }),
            DoNode::Both(left, right) => Ok(DoNode::Both(
                Box::new(left.bind_process_local_refs(process)?),
                Box::new(right.bind_process_local_refs(process)?),
            )),
            DoNode::Race(left, right) => Ok(DoNode::Race(
                Box::new(left.bind_process_local_refs(process)?),
                Box::new(right.bind_process_local_refs(process)?),
            )),
            DoNode::Let { name, value, body } => Ok(DoNode::Let {
                name: name.clone(),
                value: Box::new(value.bind_process_local_refs(process)?),
                body: Box::new(body.bind_process_local_refs(process)?),
            }),
            DoNode::Use(name) => Ok(DoNode::Use(name.clone())),
            DoNode::Acting { identity, body } => Ok(DoNode::Acting {
                identity: identity.clone(),
                body: Box::new(body.bind_process_local_refs(process)?),
            }),
            DoNode::Fail(failure) => Ok(DoNode::Fail(failure.clone())),
            DoNode::Wait(spec) => Ok(DoNode::Wait(bind_wait_spec(spec, process)?)),
            DoNode::Op(template) => Ok(DoNode::Op(bind_operation_template(template, process)?)),
        }
    }

    fn collect_ops<'a>(&'a self, out: &mut Vec<&'a OperationTemplate>) {
        match self {
            DoNode::Op(t) => out.push(t),
            DoNode::AndThen { d, .. }
            | DoNode::OrElse { d, .. }
            | DoNode::Acting { body: d, .. } => d.collect_ops(out),
            DoNode::Let { value, body, .. } => {
                value.collect_ops(out);
                body.collect_ops(out);
            }
            DoNode::Both(a, b) | DoNode::Race(a, b) => {
                a.collect_ops(out);
                b.collect_ops(out);
            }
            DoNode::Pure(_) | DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) => {}
        }
    }
}

fn bind_step_ref(step: &StepRef, process: ProcessId) -> StepRef {
    StepRef {
        process,
        name: step.name.clone(),
        arg: step.arg.clone(),
    }
}

fn bind_wait_spec(spec: &WaitSpec, process: ProcessId) -> Result<WaitSpec, PathError> {
    match spec {
        WaitSpec::Signal(path) => Ok(WaitSpec::Signal(bind_process_self_path(path, process)?)),
        WaitSpec::Deadline(at_millis) => Ok(WaitSpec::Deadline(*at_millis)),
    }
}

fn bind_operation_template(
    template: &OperationTemplate,
    process: ProcessId,
) -> Result<OperationTemplate, PathError> {
    Ok(OperationTemplate {
        target: ResourceName::new(bind_process_self_path(template.target.path(), process)?),
        method: template.method.clone(),
        method_id: template.method_id,
        output: template.output,
        literal_input: template.literal_input.clone(),
    })
}

pub(crate) fn bind_process_self_path(path: &Path, process: ProcessId) -> Result<Path, PathError> {
    let segments = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segments.first().map(|segment| segment.as_str()) != Some("process")
        || segments.get(1).map(|segment| segment.as_str()) != Some("self")
    {
        return Ok(path.clone());
    }
    let mut bound = Path::try_new("state")?
        .try_push("process")?
        .try_push(process.get().to_string())?;
    for segment in &segments[2..] {
        bound = bound.try_push(segment.as_str())?;
    }
    Ok(bound)
}

pub(crate) fn bind_process_self_capability_literal(
    literal: &str,
    process: ProcessId,
) -> Result<String, CapError> {
    let capability = Capability::parse(literal)?;
    let changed = capability.scheme == "state"
        && capability
            .segments
            .first()
            .is_some_and(|segment| segment.as_str() == "process")
        && capability
            .segments
            .get(1)
            .is_some_and(|segment| segment.as_str() == "self");
    if !changed {
        return Ok(literal.to_string());
    }

    let mut segments = Vec::with_capacity(capability.segments.len());
    for (index, segment) in capability.segments.iter().enumerate() {
        if index == 1 {
            segments.push(process.get().to_string());
        } else {
            segments.push(segment.to_string());
        }
    }
    let mut bound = format!(
        "{}://{}/{}",
        capability.verb,
        capability.scheme,
        segments.join("/")
    );
    if let Some(predicate) = &capability.predicate {
        bound.push_str(&format_predicate(predicate));
    }
    Capability::parse(&bound)?;
    Ok(bound)
}

fn format_predicate(predicate: &Predicate) -> String {
    let op = match predicate.op {
        PredOp::Eq => "=",
        PredOp::Ne => "!=",
        PredOp::Le => "<=",
        PredOp::Lt => "<",
        PredOp::Ge => ">=",
        PredOp::Gt => ">",
    };
    format!("@{}{}{}", predicate.key, op, predicate.value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, anyhow, bail, ensure};
    use xolotl_types::{ProcessId, ResourceName};

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
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
        match d {
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
        match d {
            DoNode::OrElse { d: outer_d, or } => {
                ensure!(or.name == "again", "unexpected outer step: {:?}", or.name);
                match *outer_d {
                    DoNode::OrElse { d: inner_d, or } => {
                        ensure!(or.name == "again", "unexpected inner step: {:?}", or.name);
                        ensure!(
                            matches!(*inner_d, DoNode::Op(_)),
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
        let d = DoNode::r#let("x", DoNode::pure(Value::Int(1)), DoNode::use_("x"));
        let s = serde_json::to_string(&d)?;
        let back: DoNode = serde_json::from_str(&s)?;
        ensure!(d == back, "round trip changed node: {back:?}");
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
        match bound {
            DoNode::Both(_, right) => match *right {
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

        let value = DoNode::pure(Value::Str("state://process/self/not-a-path".into()));
        ensure!(
            value.bind_process_local_refs(process)? == value,
            "plain string value should not be rebound"
        );
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
