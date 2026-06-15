#![forbid(unsafe_code)]

//! `nexus-actors` — the standard in-process Drivers / Providers.
//!
//! Each module is a [`Driver`](nexus_kernel::Driver) implementing one
//! `effect://…` Resource's methods. They are registered through the kernel's
//! standard assembly face (`Bootstrap::register_effect`) — the kernel has no
//! special loading path for built-ins vs external providers.
//!
//! Method dispatch convention: each driver's methods are listed in a
//! `*_METHODS` table in registration order; the method's index in that table
//! is its `MethodId`, which the driver matches on.

#[cfg(feature = "standard-core")]
pub mod approval;
#[cfg(feature = "standard-core")]
pub mod blob;
#[cfg(feature = "standard-core")]
pub mod compress;
#[cfg(feature = "standard-core")]
pub mod context;
#[cfg(feature = "standard-core")]
pub mod deliberation;
#[cfg(feature = "external-session")]
pub mod endpoint;
#[cfg(feature = "standard-core")]
pub mod events;
#[cfg(feature = "standard-core")]
pub mod fact;
#[cfg(feature = "fetch")]
pub mod fetch;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "standard-core")]
pub mod index;
#[cfg(feature = "standard-core")]
pub mod inference;
#[cfg(feature = "standard-core")]
pub mod inspect;
#[cfg(feature = "standard-core")]
pub mod install;
#[cfg(feature = "standard-core")]
pub mod lock;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "standard-core")]
pub mod memory;
#[cfg(feature = "external-session")]
pub mod pairing;
#[cfg(feature = "proc")]
pub mod proc;
#[cfg(feature = "standard-core")]
pub mod rank;
#[cfg(feature = "standard-core")]
pub mod router;
#[cfg(feature = "standard-core")]
pub mod state;
#[cfg(feature = "standard-core")]
pub mod tensor;
#[cfg(feature = "terminal")]
pub mod terminal;
#[cfg(feature = "standard-core")]
pub mod time;

#[cfg(feature = "standard-core")]
pub use approval::{APPROVAL_METHODS, ApprovalDriver};
#[cfg(feature = "standard-core")]
pub use blob::{BLOB_METHODS, BlobDriver};
#[cfg(feature = "standard-core")]
pub use context::{CONTEXT_METHODS, ContextDriver};
#[cfg(feature = "standard-core")]
pub use deliberation::{DELIBERATION_METHODS, DeliberationDriver, Mode};
#[cfg(feature = "standard-core")]
pub use events::{EVENTS_METHODS, EventBusDriver};
#[cfg(feature = "standard-core")]
pub use fact::{FACT_METHODS, FactDriver};
#[cfg(feature = "fetch")]
pub use fetch::{FETCH_METHODS, FetchDriver, validate_url};
#[cfg(feature = "fs")]
pub use fs::{FS_METHODS, FsDriver};
#[cfg(feature = "standard-core")]
pub use index::{INDEX_METHODS, IndexDriver};
#[cfg(feature = "standard-core")]
pub use inference::{
    BASELINE_EMBEDDING_SPACE, EchoBackend, INFERENCE_METHODS, InferenceBackend, InferenceDriver,
};
#[cfg(feature = "standard-core")]
pub use inspect::{INSPECT_METHODS, KernelInspectDriver};
#[cfg(feature = "standard-core")]
pub use install::{InstallError, StandardConfig, install_standard};
#[cfg(feature = "mcp")]
pub use install::{McpToolMount, register_mcp_tool};
#[cfg(feature = "standard-core")]
pub use lock::{LOCK_METHODS, LockDriver};
#[cfg(feature = "mcp")]
pub use mcp::{
    EchoMcpClient, MCP_STREAM_TOOL_METHODS, MCP_TOOL_METHODS, McpClient, McpToolDescriptor,
    McpToolDriver, expose_as_mcp_tool,
};
#[cfg(feature = "standard-core")]
pub use memory::{MEMORY_METHODS, MemoryDriver};
#[cfg(feature = "external-session")]
pub use pairing::{
    DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW, PAIRING_METHODS, PairingDisplayEdge, PairingDriver,
    SecureEnvelopeReplayWindow,
};
#[cfg(feature = "proc")]
pub use proc::{PROC_METHODS, ProcDriver, reconcile};
#[cfg(feature = "standard-core")]
pub use rank::{RANK_METHODS, RankerDriver};
#[cfg(feature = "terminal")]
pub use terminal::{TERMINAL_METHODS, TerminalDriver};
#[cfg(feature = "standard-core")]
pub use time::{TIME_METHODS, TimeDriver};
