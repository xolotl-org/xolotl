#![cfg_attr(not(feature = "host"), no_std)]
#![forbid(unsafe_code)]

//! Xolotl SDK. The default build exports only the allocator-free core.
//! Enable `program` for portable compilation, `runtime` for cooperative execution,
//! invocation, scope and stream composition, `host` for Tokio, `plan` for YAML/JSON plans,
//! and `standard` for providers.

pub use xolotl_core as core;
#[cfg(feature = "program")]
pub use xolotl_graph::portable::{CompileLimits, CompiledProgram, Expression, Program, Transform};
#[cfg(feature = "runtime")]
pub use xolotl_kernel as runtime;
#[cfg(feature = "runtime")]
pub use xolotl_state as state;
#[cfg(feature = "program")]
pub use xolotl_types as types;
#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::*;
