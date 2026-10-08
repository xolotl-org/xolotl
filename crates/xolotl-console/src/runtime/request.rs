//! Owned Rust runtime requests. Transports decode into the same execution path.

use xolotl_graph::{OperationTemplate, portable::Program};
use xolotl_types::{BudgetSpec, Value};

/// Original host-lifetime submission identity. It grants no authority and does
/// not resume execution after a host restart. Retain it on retries; a new nonce
/// or epoch denotes new work. The host publishes its current registry scope.
///
/// The immutable account instance and normalized program, input semantics,
/// caller budget and optional timeout bind acceptance. Visibility justification,
/// session and descriptor revision do not change that work identity; each call
/// still authenticates and validates its own header. A matching accepted retry
/// returns only the original execution reference and acceptance/retirement
/// evidence, without preparing a new program or extending its deadline. Result
/// retrieval checks current authority separately. Preparing is not acceptance;
/// missing evidence never proves non-execution.
///
/// Open-range aliases retain bounded hashes and references, not request inputs,
/// under the execution directory's logical capacity. Forgetting an execution
/// does not release its open retry alias. Trusted hosts close ranges through
/// [`crate::ConsoleService::close_submission_retry_epoch`]; unknown identities
/// in closed ranges reject before effects. A replacement registry rejects the
/// original instance rather than reinterpreting it as new work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSubmissionIdentity {
    /// Original execution registry instance, not a session or username.
    pub registry_instance: String,
    /// Original retry range. Closed unknown identities cannot execute anew.
    pub retry_epoch: u64,
    /// Client-chosen literal nonce: 1..=256 ASCII alphanumeric or `-_.:` bytes.
    /// It is not trimmed and is hashed before retention.
    pub nonce: String,
}

/// Code supplied to one Console runtime call. Host resource installation and
/// authority remain separate from this request.
#[derive(Clone, Debug)]
pub enum RuntimeCode {
    /// Invoke one installed resource method.
    Operation {
        /// Installed resource method and requested output mode.
        operation: OperationTemplate,
    },
    /// Execute an already constructed portable program without a JSON round trip.
    Program(Program),
}

/// An owned Rust request for an attached call, subscription or independent
/// submission. The service applies the same authentication, exposure, grant,
/// audit and execution checks as its protocol entry points.
#[derive(Clone, Debug)]
pub struct RuntimeRequest {
    /// Resource operation or portable program to run.
    pub code: RuntimeCode,
    /// Value entering the operation or program.
    pub input: Value,
    /// Additional process-tree budget ceiling, intersected with the host's.
    pub budget: BudgetSpec,
    /// Optional execution deadline relative to admission, in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Explicit visibility scope required for runtime execution.
    pub scope: String,
    /// Operator reason recorded in the mutation or visibility audit.
    pub justification: String,
    /// Visibility grant duration for this request, in milliseconds.
    pub ttl_ms: u64,
    /// Optional descriptor revision precondition.
    pub registry_rev: Option<u64>,
    /// Optional explicit retry identity for service-owned submission only.
    /// Without it, each submission is distinct and response loss is not retry-safe.
    pub submission_identity: Option<RuntimeSubmissionIdentity>,
}

impl RuntimeRequest {
    /// Build a request with no additional budget or duration restriction.
    pub fn new(
        code: RuntimeCode,
        input: Value,
        scope: impl Into<String>,
        justification: impl Into<String>,
        ttl_ms: u64,
    ) -> Self {
        Self {
            code,
            input,
            budget: BudgetSpec::default(),
            timeout_ms: None,
            scope: scope.into(),
            justification: justification.into(),
            ttl_ms,
            registry_rev: None,
            submission_identity: None,
        }
    }
}
