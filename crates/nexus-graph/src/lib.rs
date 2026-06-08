#![forbid(unsafe_code)]

//! `nexus-graph` — the single execution IR and its front-ends.
//!
//! Every Program format (`Do<A>`, model plan, native) compiles to one
//! [`ExecutionGraph`] (§13.2). The Executor (in `nexus-kernel`) only ever
//! advances a graph cursor — it never interprets a source format directly.
//! This is what makes "format independence" a fact rather than a slogan: many
//! front-ends, one IR, one Executor, one recovery story.
//!
//! This crate sits **below** the kernel and **above** `nexus-types` (§24.2),
//! and is wasm-safe: the Do→Graph compiler can run in the browser.
//!
//! - [`graph`]   — `ExecutionGraph` / `Node` / `NodeKind`, the IR.
//! - `r#do`      — `Do<A>` (`DoNode`): the preferred serializable front-end.
//! - [`compile`] — Do→Graph compiler; assigns stable `NodeId == CausalPosition`.
//! - [`cursor`]  — `GraphCursor`: where execution / recovery is positioned.
//! - [`actor_spec`] — `ActorSpec` + `lint`: declared vs. used effects (§20.2/§21.5).

pub mod actor_spec;
pub mod compile;
pub mod cursor;
#[path = "do_.rs"]
pub mod r#do;
pub mod graph;

pub use actor_spec::{ActorSpec, LintFinding, LintSeverity, capability_covers, lint};
pub use compile::{CompileError, compile_do, compile_do_at};
pub use cursor::{Frame, GraphCursor};
pub use r#do::DoNode;
pub use graph::{
    BranchKind, Edge, EdgeKind, ExecutionGraph, JoinKind, Node, NodeKind, OperationTemplate,
    StepRef, WaitSpec,
};
