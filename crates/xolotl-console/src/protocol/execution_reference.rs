//! Execution references shared by successful and failed calls.

use serde::{Deserialize, Serialize};

/// An allocated kernel execution. This reference grants no observation authority
/// and does not guarantee retention, rollback, or safe retry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReference {
    /// Opaque Console execution ID when the service owns a retained record.
    /// Absent for request-owned calls and subscriptions.
    pub execution_id: Option<String>,
    /// Kernel process ID as a decimal string, avoiding JSON number precision loss.
    pub process_id: String,
    /// Content-addressed prepared program ID in lowercase hexadecimal.
    pub program_id: String,
}
