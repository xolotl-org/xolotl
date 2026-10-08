//! Canonical targets for built-in effects shared by hosts and clients.
//!
//! These names identify resources, not an implementation requirement: a host
//! may register its own drivers at the same targets or omit them entirely.

/// Read-only process inspection effect.
pub const KERNEL_PROCESS_INSPECT: &str = "effect://kernel/process/inspect";

/// Spawn an external process.
pub const PROC_SPAWN: &str = "effect://proc/spawn";
/// Kill an external process.
pub const PROC_KILL: &str = "effect://proc/kill";
/// Send a signal to an external process.
pub const PROC_SIGNAL: &str = "effect://proc/signal";
/// Inspect an external process status.
pub const PROC_STATUS: &str = "effect://proc/status";
/// Update an external process heartbeat.
pub const PROC_HEARTBEAT: &str = "effect://proc/heartbeat";
/// Built-in external process effect targets in registration order.
pub const PROC_TARGETS: [&str; 5] = [
    PROC_SPAWN,
    PROC_KILL,
    PROC_SIGNAL,
    PROC_STATUS,
    PROC_HEARTBEAT,
];

/// Create an external pairing intent.
pub const PAIRING_CREATE: &str = "effect://external/pairing/create";
/// Approve an external pairing intent.
pub const PAIRING_APPROVE: &str = "effect://external/pairing/approve";
/// Deny an external pairing intent.
pub const PAIRING_DENY: &str = "effect://external/pairing/deny";
/// Revoke an external credential.
pub const EXTERNAL_REVOKE: &str = "effect://external/revoke";
/// Built-in pairing and revocation effect targets in registration order.
pub const PAIRING_TARGETS: [&str; 4] = [
    PAIRING_CREATE,
    PAIRING_APPROVE,
    PAIRING_DENY,
    EXTERNAL_REVOKE,
];
