//! Approval Broker: `effect://approval/ask`,
//! `effect://approval/check`, `effect://approval/respond`.
//!
//! `ask` records a pending approval keyed by `dedup_key`; duplicate asks reuse
//! the original record. An ask carries a **fanout policy**:
//! `AnyOne`, where the first responder decides, or `RequireAll`, where every
//! listed approver must approve. It may also carry a **deadline** in
//! milliseconds since epoch.
//!
//! `respond` records one approver's decision and re-resolves the record under
//! its fanout policy. A real broker drives responses from human input through a
//! gateway; `respond` is the driver entry point that gateway calls.
//!
//! `check` is a pure read of whether a key is decided, reported as a status
//! string (`pending` / `approved` / `denied` / `expired`), so Policy `Ask`
//! checks can consult it without re-issuing the ask. `check` reports
//! `expired` once the Kernel host clock is past the deadline while still pending.
//! Responses compare the complete observed record before committing; conflicts
//! reread and re-resolve without overwriting a terminal decision.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, MethodSpec, host::HostRuntime,
};
use xolotl_state::Backend;
use xolotl_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};
use xolotl_types::{ValueMap, ValueView};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://approval/<method>` Resource with public method
/// `invoke`.
pub(crate) const APPROVAL_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "ask",
        xolotl_types::MethodAuthority::Perform,
        Purity::Idempotent,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "check",
        xolotl_types::MethodAuthority::Perform,
        Purity::Pure,
        MethodSpec::UNARY_ASYNC,
    )
    .observes_external(),
    MethodSpec::new(
        "respond",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
];

const STATUS_PENDING: &str = "pending";
const STATUS_APPROVED: &str = "approved";
const STATUS_DENIED: &str = "denied";
const STATUS_EXPIRED: &str = "expired";

/// How an ask is resolved from responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fanout {
    /// First responder decides (`fanout=AnyOne`).
    AnyOne,
    /// Every listed approver must approve; any denial decides `denied`.
    RequireAll,
}

impl Fanout {
    fn as_str(self) -> &'static str {
        match self {
            Fanout::AnyOne => "any_one",
            Fanout::RequireAll => "require_all",
        }
    }
    fn parse(s: &str) -> Result<Fanout, DriverError> {
        match s {
            "any_one" | "any" => Ok(Fanout::AnyOne),
            "require_all" | "all" => Ok(Fanout::RequireAll),
            _ => Err(DriverError::InvalidInput(format!(
                "invalid approval fanout {s:?}"
            ))),
        }
    }
}

/// The persisted approval record. Stored as a a `Value` map so it lives in the
/// state plane and travels with taint like any other value.
#[derive(Clone, Debug, PartialEq)]
struct Record {
    status: String,
    fanout: Fanout,
    /// The approver set. For `RequireAll` this is the quorum that must all
    /// approve; empty means "any single approval suffices".
    approvers: Vec<String>,
    /// Deadline in millis since epoch; `0` = no deadline.
    deadline_millis: i64,
    approvals: Vec<String>,
    denials: Vec<String>,
}

impl Record {
    fn pending(fanout: Fanout, approvers: Vec<String>, deadline_millis: i64) -> Self {
        Self {
            status: STATUS_PENDING.into(),
            fanout,
            approvers,
            deadline_millis,
            approvals: Vec::new(),
            denials: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("status".into(), Value::string(self.status.clone()));
        m.insert("fanout".into(), Value::string(self.fanout.as_str().into()));
        m.insert(
            "deadline_millis".into(),
            Value::integer(self.deadline_millis),
        );
        m.insert("approvers".into(), str_list(&self.approvers));
        m.insert("approvals".into(), str_list(&self.approvals));
        m.insert("denials".into(), str_list(&self.denials));
        Value::map(m)
    }

    fn from_value(v: &Value) -> Result<Self, DriverError> {
        let m = v
            .as_map()
            .ok_or_else(|| DriverError::Other("malformed approval record: not a map".into()))?;
        let status = required_record_str(m, "status")?;
        match status {
            STATUS_PENDING | STATUS_APPROVED | STATUS_DENIED | STATUS_EXPIRED => {}
            other => {
                return Err(DriverError::Other(format!(
                    "malformed approval record: invalid status {other:?}"
                )));
            }
        }
        let deadline_millis = required_record_int(m, "deadline_millis")?;
        if deadline_millis < 0 {
            return Err(DriverError::Other(
                "malformed approval record: negative deadline_millis".into(),
            ));
        }
        Ok(Self {
            status: status.into(),
            fanout: Fanout::parse(required_record_str(m, "fanout")?)?,
            approvers: parse_str_list(m.get("approvers"), "record.approvers")?,
            deadline_millis,
            approvals: parse_str_list(m.get("approvals"), "record.approvals")?,
            denials: parse_str_list(m.get("denials"), "record.denials")?,
        })
    }

    /// True once a terminal decision is recorded.
    fn is_decided(&self) -> bool {
        self.status != STATUS_PENDING
    }

    /// Effective status given `now`: a still-pending record past its deadline is
    /// reported `expired` without mutating the stored record (a pure read).
    fn effective_status(&self, now: i64) -> &str {
        if self.status == STATUS_PENDING && self.deadline_millis > 0 && now > self.deadline_millis {
            STATUS_EXPIRED
        } else {
            &self.status
        }
    }

    /// Apply one approver's decision and re-resolve under the fanout policy.
    fn apply(&mut self, approver: &str, approve: bool) {
        if approve {
            if !self.approvals.iter().any(|a| a == approver) {
                self.approvals.push(approver.to_string());
            }
        } else if !self.denials.iter().any(|a| a == approver) {
            self.denials.push(approver.to_string());
        }
        self.resolve();
    }

    fn resolve(&mut self) {
        // A denial always decides `denied` (a single veto blocks the action).
        if !self.denials.is_empty() {
            self.status = STATUS_DENIED.into();
            return;
        }
        match self.fanout {
            // First approval decides.
            Fanout::AnyOne => {
                if !self.approvals.is_empty() {
                    self.status = STATUS_APPROVED.into();
                }
            }
            // Every listed approver must approve. With no explicit quorum,
            // RequireAll degrades to "one approval" (there is no set to satisfy).
            Fanout::RequireAll => {
                let satisfied = if self.approvers.is_empty() {
                    !self.approvals.is_empty()
                } else {
                    self.approvers
                        .iter()
                        .all(|a| self.approvals.iter().any(|x| x == a))
                };
                if satisfied {
                    self.status = STATUS_APPROVED.into();
                }
            }
        }
    }
}

fn str_list(xs: &[String]) -> Value {
    Value::list(xs.iter().map(|s| Value::string(s.clone())).collect())
}

fn required_record_str<'a>(m: &'a ValueMap, field: &'static str) -> Result<&'a str, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value),
        Some(ValueView::Str(_)) => Err(DriverError::Other(format!(
            "malformed approval record: {field} must not be empty"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "malformed approval record: {field} must be a string"
        ))),
        None => Err(DriverError::Other(format!(
            "malformed approval record: missing {field}"
        ))),
    }
}

fn required_record_int(m: &ValueMap, field: &'static str) -> Result<i64, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Int(value)) => Ok(value),
        Some(_) => Err(DriverError::Other(format!(
            "malformed approval record: {field} must be an integer"
        ))),
        None => Err(DriverError::Other(format!(
            "malformed approval record: missing {field}"
        ))),
    }
}

fn parse_str_list(v: Option<&Value>, field: &'static str) -> Result<Vec<String>, DriverError> {
    match v.map(Value::view) {
        None => Ok(Vec::new()),
        Some(ValueView::List(items)) => items
            .iter()
            .map(|item| match item.view() {
                ValueView::Str(value) if !value.is_empty() => Ok(value.to_owned()),
                ValueView::Str(_) => Err(DriverError::InvalidInput(format!(
                    "{field} must not contain empty strings"
                ))),
                _ => Err(DriverError::InvalidInput(format!(
                    "{field} must contain only strings"
                ))),
            })
            .collect(),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{field} must be a string list"
        ))),
    }
}

/// Drives the approval actions.
pub(crate) struct ApprovalDriver {
    state: Backend,
    host_runtime: HostRuntime,
}

impl ApprovalDriver {
    /// Create an approval broker backed by the state plane.
    pub(crate) fn new(state: Backend, host_runtime: HostRuntime) -> Self {
        Self {
            state,
            host_runtime,
        }
    }

    /// Build an approval record's path. `key` arrives from Operation input, so
    /// an illegal path segment is a caller error (returned as `DriverError`),
    /// never a panic.
    fn key_path(key: &str) -> Result<Path, DriverError> {
        Path::try_new("state")
            .and_then(|path| path.try_push("kernel"))
            .and_then(|path| path.try_push("approvals"))
            .and_then(|path| path.try_push_literal(key))
            .map_err(|e| DriverError::Other(format!("invalid approval key {key:?}: {e}")))
    }

    async fn read_record(
        &self,
        path: &Path,
        observed: &mut xolotl_types::TaintSet,
    ) -> Result<Option<(Value, Record)>, ObservedFailure> {
        let v = self
            .state
            .read_tainted(path)
            .await
            .map_err(ObservedFailure::from)?;
        observed.union(&v.taint);
        match v.value {
            Some(value) => {
                let record = Record::from_value(&value).map_err(ObservedFailure::from)?;
                Ok(Some((value, record)))
            }
            None => Ok(None),
        }
    }

    async fn respond_record(
        &self,
        path: &Path,
        approver: &str,
        approve: bool,
        observed: &mut xolotl_types::TaintSet,
    ) -> Result<String, ObservedFailure> {
        for _ in 0..8 {
            let (expected, mut record) =
                self.read_record(path, observed).await?.ok_or_else(|| {
                    DriverError::Other("approval record missing during response".into())
                })?;
            if record.is_decided() {
                return Ok(record.status);
            }
            if record.effective_status(self.host_runtime.now_millis()) == STATUS_EXPIRED {
                record.status = STATUS_EXPIRED.into();
            } else {
                record.apply(approver, approve);
            }
            match self
                .state
                .write_cas_tainted(path, Some(expected), record.to_value(), observed.clone())
                .await
            {
                Ok(commit) => {
                    observed.union(&commit.taint);
                    return Ok(record.status);
                }
                Err(xolotl_state::StateFailure {
                    error: xolotl_state::StateError::CasFailed { .. },
                    taint,
                }) => observed.union(&taint),
                Err(error) => return Err(error.into()),
            }
        }
        Err(DriverError::Other("approval response CAS retries exhausted".into()).into())
    }
}

fn required_input_str<'a>(m: &'a ValueMap, field: &'static str) -> Result<&'a str, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(format!(
            "approval {field} must not be empty"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "approval {field} must be a string"
        ))),
        None => Err(DriverError::InvalidInput(format!(
            "approval requires {field}"
        ))),
    }
}

fn optional_fanout(m: &ValueMap) -> Result<Fanout, DriverError> {
    match m.get("fanout").map(Value::view) {
        None => Ok(Fanout::AnyOne),
        Some(ValueView::Str(value)) => Fanout::parse(value),
        Some(_) => Err(DriverError::InvalidInput(
            "approval fanout must be a string".into(),
        )),
    }
}

fn optional_non_negative_int(
    m: &ValueMap,
    field: &'static str,
    default: i64,
) -> Result<i64, DriverError> {
    match m.get(field).map(Value::view) {
        None => Ok(default),
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(format!(
            "approval {field} must be non-negative"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "approval {field} must be an integer"
        ))),
    }
}

fn decision_from(m: &ValueMap) -> Result<bool, DriverError> {
    match m.get("decision").map(Value::view) {
        Some(ValueView::Str(decision)) => match decision {
            "approve" | "approved" | "yes" => return Ok(true),
            "deny" | "denied" | "no" => return Ok(false),
            other => {
                return Err(DriverError::InvalidInput(format!(
                    "invalid approval decision {other:?}"
                )));
            }
        },
        Some(_) => {
            return Err(DriverError::InvalidInput(
                "approval decision must be a string".into(),
            ));
        }
        None => {}
    }
    match m.get("approve").map(Value::view) {
        Some(ValueView::Bool(value)) => Ok(value),
        Some(_) => Err(DriverError::InvalidInput(
            "approval approve must be a bool".into(),
        )),
        None => Err(DriverError::InvalidInput(
            "respond requires decision=approve|deny".into(),
        )),
    }
}

impl ApprovalDriver {
    async fn execute(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
        observed: &mut xolotl_types::TaintSet,
    ) -> Result<DriverOutput, ObservedFailure> {
        let m = crate::input::map(input, "approval")?;
        if m.contains_key("now_millis") {
            return Err(DriverError::InvalidInput(
                "approval time is owned by the host clock".into(),
            )
            .into());
        }
        let key = required_input_str(&m, "dedup_key")?.to_string();
        let path = Self::key_path(&key)?;
        match method.get() {
            // ask: create-if-absent a pending record carrying the fanout policy,
            // approver set, and deadline. Later asks merge (Cas{None} no-ops).
            0 => {
                let fanout = optional_fanout(&m)?;
                let approvers = parse_str_list(m.get("approvers"), "approvers")?;
                let deadline = optional_non_negative_int(&m, "deadline_millis", 0)?;
                let record = Record::pending(fanout, approvers, deadline);
                match self
                    .state
                    .write_cas_tainted(&path, None, record.to_value(), ctx.taint.clone())
                    .await
                {
                    Ok(commit) => observed.union(&commit.taint),
                    Err(xolotl_state::StateFailure {
                        error: xolotl_state::StateError::CasFailed { .. },
                        taint,
                    }) => observed.union(&taint),
                    Err(error) => return Err(error.into()),
                }
                let (_value, current) =
                    self.read_record(&path, observed).await?.ok_or_else(|| {
                        DriverError::Other("approval record missing after ask".into())
                    })?;
                Ok(DriverOutput::new(Outcome::Done(current.to_value())))
            }
            // check: pure read of the current decision, reported as a status
            // string. Reports `expired` once now > deadline while pending.
            1 => {
                let status = match self.read_record(&path, observed).await? {
                    Some((_value, record)) => record
                        .effective_status(self.host_runtime.now_millis())
                        .to_string(),
                    None => return Ok(DriverOutput::new(Outcome::Done(Value::null()))),
                };
                Ok(DriverOutput::new(Outcome::Done(Value::string(status))))
            }
            // respond: an approver records approve/deny; re-resolve under fanout.
            2 => {
                let approver = required_input_str(&m, "approver")?.to_string();
                let approve = decision_from(&m)?;
                let status = self
                    .respond_record(&path, &approver, approve, observed)
                    .await?;
                Ok(DriverOutput::new(Outcome::Done(Value::string(status))))
            }
            _ => Err(DriverError::NoSuchMethod(method).into()),
        }
    }
}

#[async_trait]
impl Driver for ApprovalDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let mut observed = ctx.taint.clone();
        match self
            .execute(method, input, output, ctx, &mut observed)
            .await
        {
            Ok(mut output) => {
                output.taint.union(&observed);
                Ok(output)
            }
            Err(error) => error.with_taint(&observed).into_output("approval"),
        }
    }
}

#[cfg(test)]
mod tests {
    mod consistency;

    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{IdentityRef, ProcessId};

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn driver() -> ApprovalDriver {
        ApprovalDriver::new(
            InMemoryBackend::new().into_backend(),
            HostRuntime::default(),
        )
    }

    fn ask(key: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string(key.into()));
        Value::map(m)
    }

    async fn check(d: &ApprovalDriver, key: &str) -> Result<String> {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string(key.into()));
        match d
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("check approval status")?
            .outcome
        {
            Outcome::Done(value) => value
                .as_str()
                .map(str::to_owned)
                .context("expected status string"),
            other => bail!("expected status string, got {other:?}"),
        }
    }

    async fn respond(
        d: &ApprovalDriver,
        key: &str,
        approver: &str,
        decision: &str,
    ) -> Result<String> {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string(key.into()));
        m.insert("approver".into(), Value::string(approver.into()));
        m.insert("decision".into(), Value::string(decision.into()));
        match d
            .call(MethodId::new(2), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("respond to approval")?
            .outcome
        {
            Outcome::Done(value) => value
                .as_str()
                .map(str::to_owned)
                .context("expected status string"),
            other => bail!("expected status string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ask_is_idempotent_per_key() -> Result<()> {
        let d = driver();
        let a = d
            .call(MethodId::new(0), ask("pay-42"), OutputMode::Unary, &ctx())
            .await
            .context("first approval ask")?;
        let b = d
            .call(MethodId::new(0), ask("pay-42"), OutputMode::Unary, &ctx())
            .await
            .context("duplicate approval ask")?;
        ensure!(a == b, "duplicate approval ask: expected {a:?}, got {b:?}");
        let status = check(&d, "pay-42").await?;
        ensure!(status == "pending", "pending approval status: {status:?}");
        Ok(())
    }

    #[tokio::test]
    async fn ask_rejects_key_path_delimiters() -> Result<()> {
        let d = driver();
        let out = d
            .call(MethodId::new(0), ask("pay/42"), OutputMode::Unary, &ctx())
            .await;
        ensure!(
            out.is_err(),
            "approval key with path delimiter was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ask_rejects_malformed_options() -> Result<()> {
        let d = driver();
        let mut bad_fanout = BTreeMap::new();
        bad_fanout.insert("dedup_key".into(), Value::string("bad-fanout".into()));
        bad_fanout.insert("fanout".into(), Value::string("sometimes".into()));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(bad_fanout),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "invalid fanout was accepted");

        let mut bad_deadline = BTreeMap::new();
        bad_deadline.insert("dedup_key".into(), Value::string("bad-deadline".into()));
        bad_deadline.insert("deadline_millis".into(), Value::integer(-1));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(bad_deadline),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "negative deadline was accepted");

        let mut bad_approver = BTreeMap::new();
        bad_approver.insert("dedup_key".into(), Value::string("bad-approver".into()));
        bad_approver.insert(
            "approvers".into(),
            Value::list(vec![Value::string("alice".into()), Value::integer(1)]),
        );
        let out = d
            .call(
                MethodId::new(0),
                Value::map(bad_approver),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "non-string approver was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn any_one_resolves_on_first_approve() -> Result<()> {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string("deploy".into()));
        m.insert("fanout".into(), Value::string("any_one".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("ask approval")?;
        let pending = check(&d, "deploy").await?;
        ensure!(pending == "pending", "initial approval status: {pending:?}");
        let approved = respond(&d, "deploy", "alice", "approve").await?;
        ensure!(
            approved == "approved",
            "approval response status: {approved:?}"
        );
        let status = check(&d, "deploy").await?;
        ensure!(status == "approved", "resolved approval status: {status:?}");
        Ok(())
    }

    #[tokio::test]
    async fn require_all_needs_every_approver() -> Result<()> {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string("wire".into()));
        m.insert("fanout".into(), Value::string("require_all".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("ask approval")?;
        let first = respond(&d, "wire", "alice", "approve").await?;
        ensure!(first == "pending", "partial quorum status: {first:?}");
        let pending = check(&d, "wire").await?;
        ensure!(pending == "pending", "partial quorum check: {pending:?}");
        let second = respond(&d, "wire", "bob", "approve").await?;
        ensure!(second == "approved", "full quorum status: {second:?}");
        let status = check(&d, "wire").await?;
        ensure!(status == "approved", "full quorum check: {status:?}");
        Ok(())
    }

    #[tokio::test]
    async fn require_all_denied_by_single_veto() -> Result<()> {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string("merge".into()));
        m.insert("fanout".into(), Value::string("require_all".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("ask approval")?;
        let first = respond(&d, "merge", "alice", "approve").await?;
        ensure!(first == "pending", "pre-veto status: {first:?}");
        let denied = respond(&d, "merge", "bob", "deny").await?;
        ensure!(denied == "denied", "veto status: {denied:?}");
        let status = check(&d, "merge").await?;
        ensure!(status == "denied", "veto check: {status:?}");
        Ok(())
    }

    #[tokio::test]
    async fn respond_rejects_invalid_decision() -> Result<()> {
        let d = driver();
        d.call(MethodId::new(0), ask("decision"), OutputMode::Unary, &ctx())
            .await
            .context("ask approval")?;
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::string("decision".into()));
        m.insert("approver".into(), Value::string("alice".into()));
        m.insert("decision".into(), Value::string("maybe".into()));
        m.insert("approve".into(), Value::boolean(true));
        let out = d
            .call(MethodId::new(2), Value::map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "invalid decision was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn malformed_stored_record_is_an_error() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ApprovalDriver::new(state.clone(), HostRuntime::default());
        let path = ApprovalDriver::key_path("corrupt").context("approval path")?;
        state
            .write_set(&path, Value::map(BTreeMap::new()))
            .await
            .context("write malformed approval record")?;
        let out = d
            .call(MethodId::new(1), ask("corrupt"), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "malformed approval state was ignored");
        Ok(())
    }
}
