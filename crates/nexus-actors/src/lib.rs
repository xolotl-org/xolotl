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

pub mod approval;
pub mod blob;
pub mod compress;
pub mod context;
pub mod deliberation;
pub mod endpoint;
pub mod events;
pub mod fact;
pub mod fetch;
pub mod fs;
pub mod index;
pub mod inference;
pub mod inspect;
pub mod install;
pub mod lock;
pub mod mcp;
pub mod memory;
pub mod pairing;
pub mod proc;
pub mod rank;
pub mod router;
pub mod state;
pub mod tensor;
pub mod terminal;
pub mod time;

pub use approval::{APPROVAL_METHODS, ApprovalDriver};
pub use blob::{BLOB_METHODS, BlobDriver};
pub use context::{CONTEXT_METHODS, ContextDriver};
pub use deliberation::{DELIBERATION_METHODS, DeliberationDriver, Mode};
pub use events::{EVENTS_METHODS, EventBusDriver};
pub use fact::{FACT_METHODS, FactDriver};
pub use fetch::{FETCH_METHODS, FetchDriver, validate_url};
pub use fs::{FS_METHODS, FsDriver};
pub use index::{INDEX_METHODS, IndexDriver};
pub use inference::{
    BASELINE_EMBEDDING_SPACE, EchoBackend, INFERENCE_METHODS, InferenceBackend, InferenceDriver,
};
pub use inspect::{INSPECT_METHODS, KernelInspectDriver};
pub use install::{
    InstallError, McpToolMount, StandardConfig, install_standard, register_mcp_tool,
};
pub use lock::{LOCK_METHODS, LockDriver};
pub use mcp::{
    EchoMcpClient, MCP_STREAM_TOOL_METHODS, MCP_TOOL_METHODS, McpClient, McpToolDescriptor,
    McpToolDriver, expose_as_mcp_tool,
};
pub use memory::{MEMORY_METHODS, MemoryDriver};
pub use pairing::{
    DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW, PAIRING_METHODS, PairingDisplayEdge, PairingDriver,
    SecureEnvelopeReplayWindow,
};
pub use proc::{PROC_METHODS, ProcDriver, reconcile};
pub use rank::{RANK_METHODS, RankerDriver};
pub use terminal::{TERMINAL_METHODS, TerminalDriver};
pub use time::{TIME_METHODS, TimeDriver};
