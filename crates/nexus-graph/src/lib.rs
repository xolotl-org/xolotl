#![forbid(unsafe_code)]

//! `nexus-graph` — the single execution IR and its front-ends.
//!
//! Every Program format (`Do<A>`, model plan, native) compiles to one
//! [`ExecutionGraph`]. The Executor (in `nexus-kernel`) advances a graph cursor
//! over that IR. Front-ends share the same executor and recovery model.
//!
//! This crate sits **below** the kernel and **above** `nexus-types`,
//! and is wasm-safe: the Do→Graph compiler can run in the browser.
//!
//! - [`graph`]   — `ExecutionGraph` / `Node` / `NodeKind`, the IR.
//! - `r#do`      — `Do<A>` (`DoNode`): the preferred serializable front-end.
//! - [`compile`] — Do→Graph compiler; assigns stable `NodeId == CausalPosition`.
//! - [`cursor`]  — `GraphCursor`: where execution / recovery is positioned.
//! - [`actor_spec`] — `ActorSpec` + `lint`: declared vs. used effects.

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
