#![no_std]
#![forbid(unsafe_code)]

//! Program front ends and interchange graphs for the common execution core.
//!
//! [`DoNode`] and native continuations compile to [`ExecutionGraph`], which the
//! hosted executor lowers to `xolotl-core` instructions. [`portable`] programs
//! compile directly to core images with explicit portable imports. Both paths
//! use the same core control flow; durable checkpoints require portable imports.
//!
//! This crate sits **below** the kernel and **above** `xolotl-types`,
//! and is wasm-safe: the Do→Graph compiler can run in the browser.
//!
//! - [`graph`]   — `ExecutionGraph` / `Node` / `NodeKind`, the graph interchange form.
//! - `r#do`      — `Do<A>` (`DoNode`): the native graph front end.
//! - [`compile`] — Do→Graph compiler; assigns stable `NodeId == CausalPosition`.
//! - [`actor_spec`] — `ActorSpec` + `lint`: declared vs. used effects.
//! - [`portable`] — portable expressions, compilation and import contracts.

#[macro_use]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod actor_spec;
pub mod compile;
#[path = "do_.rs"]
pub mod r#do;
mod fingerprint;
pub mod graph;
pub mod portable;

pub use actor_spec::{
    ActorBindError, ActorSpec, CapabilityQueryError, LintFinding, LintSeverity, capability_covers,
    lint, lint_actor, operation_capability_verb,
};
pub use compile::{CompileError, compile_do, compile_do_at};
pub use r#do::{DoNode, bind_process_self_capability};
pub use graph::{
    BranchKind, Edge, EdgeKind, ExecutionGraph, JoinKind, Node, NodeKind, OperationTemplate,
    StepRef, WaitSpec,
};
