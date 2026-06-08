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
use nexus_types::{Failure, Path, Value};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{ProcessId, ResourceName};

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    fn op(path: &str) -> OperationTemplate {
        OperationTemplate {
            target: ResourceName::new(Path::parse(path).unwrap()),
            method: "invoke".into(),
            method_id: None,
            output: nexus_types::OutputMode::Unary,
            literal_input: None,
        }
    }

    #[test]
    fn build_and_then_chain() {
        let d = DoNode::op(op("effect://x/post")).and_then(s("handle"));
        assert!(matches!(d, DoNode::AndThen { .. }));
    }

    #[test]
    fn map_builds_and_then() {
        // `map` is sugar for `AndThen` into a pure projecting Step.
        let d = DoNode::op(op("effect://x/post")).map(s("project"));
        match d {
            DoNode::AndThen { then, .. } => assert_eq!(then.name, "project"),
            _ => panic!("map must desugar to AndThen"),
        }
    }

    #[test]
    fn retry_zero_is_identity() {
        let d = DoNode::op(op("effect://x")).retry(0, s("again"));
        assert!(matches!(d, DoNode::Op(_)));
    }

    #[test]
    fn retry_nests_or_else() {
        // max=2 → two nested OrElse wrapping the inner Op, each routing to the
        // same recover step.
        let d = DoNode::op(op("effect://x")).retry(2, s("again"));
        match d {
            DoNode::OrElse { d: outer_d, or } => {
                assert_eq!(or.name, "again");
                match *outer_d {
                    DoNode::OrElse { d: inner_d, or } => {
                        assert_eq!(or.name, "again");
                        assert!(matches!(*inner_d, DoNode::Op(_)));
                    }
                    _ => panic!("expected nested OrElse"),
                }
            }
            _ => panic!("expected OrElse"),
        }
        // Structural bound: 1 Op + 2 OrElse wrappers = size 3.
        let d2 = DoNode::op(op("effect://x")).retry(2, s("again"));
        assert_eq!(d2.size(), 3);
    }

    #[test]
    fn collect_ops_walks_all_branches() {
        let d = DoNode::Let {
            name: "x".into(),
            value: Box::new(DoNode::op(op("effect://a"))),
            body: Box::new(DoNode::Both(
                Box::new(DoNode::op(op("effect://b"))),
                Box::new(DoNode::op(op("effect://c"))),
            )),
        };
        assert_eq!(d.ops().len(), 3);
        assert_eq!(d.size(), 5);
    }

    #[test]
    fn serde_roundtrip() {
        let d = DoNode::r#let("x", DoNode::pure(Value::Int(1)), DoNode::use_("x"));
        let s = serde_json::to_string(&d).unwrap();
        let back: DoNode = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn fail_is_terminal() {
        let d = DoNode::fail(Failure::Cancelled);
        assert_eq!(d.size(), 1);
        assert!(d.ops().is_empty());
    }
}
