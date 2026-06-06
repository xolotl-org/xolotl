//! Approval Broker (§17.4): `effect://approval/ask`,
//! `effect://approval/check`, `effect://approval/respond`.
//!
//! `ask` records a pending approval keyed by `dedup_key`; duplicate asks merge
//! (§17.4 "同 dedup_key 合并为一次询问"). An ask carries a **fanout policy** —
//! `AnyOne` (首答生效, first responder decides) or `RequireAll` (全到齐才返回,
//! all listed approvers must approve) — and an optional **deadline** in millis
//! since epoch (§17.4 "timeout 用子 Process 的 Deadline 实现").
//!
//! `respond` records one approver's decision and re-resolves the record under
//! its fanout policy. A real broker drives responses from human input through a
//! gateway; `respond` is the in-spine seam that gateway calls.
//!
//! `check` is a pure read of whether a key is decided, reported as a status
//! string (`pending` / `approved` / `denied` / `expired`), so Policy `Ask`
//! checks (§8) can consult it without re-issuing the ask. `check` reports
//! `expired` once `now > deadline` while still pending; `now` comes from a
//! `now_millis` input field when supplied (deterministic replay, §9.3), else the
//! wall clock.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::Backend;
use nexus_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};
use std::collections::BTreeMap;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://approval/<method>` Resource with public method
/// `invoke`.
pub const APPROVAL_METHODS: &[MethodSpec] = &[
    MethodSpec::new("ask", Purity::Idempotent, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("check", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("respond", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

const STATUS_PENDING: &str = "pending";
const STATUS_APPROVED: &str = "approved";
const STATUS_DENIED: &str = "denied";
const STATUS_EXPIRED: &str = "expired";

/// How an ask is resolved from responses (§17.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fanout {
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
    fn parse(s: Option<&str>) -> Fanout {
        match s {
            Some("require_all") | Some("all") => Fanout::RequireAll,
            _ => Fanout::AnyOne,
        }
    }
}

/// The persisted approval record. Stored as a `Value::Map` so it lives in the
/// ordinary state plane (§12) and travels with taint like any other value.
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
        m.insert("status".into(), Value::Str(self.status.clone()));
        m.insert("fanout".into(), Value::Str(self.fanout.as_str().into()));
        m.insert("deadline_millis".into(), Value::Int(self.deadline_millis));
        m.insert("approvers".into(), str_list(&self.approvers));
        m.insert("approvals".into(), str_list(&self.approvals));
        m.insert("denials".into(), str_list(&self.denials));
        Value::Map(m)
    }

    fn from_value(v: &Value) -> Option<Self> {
        let m = v.as_map()?;
        Some(Self {
            status: m
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or(STATUS_PENDING)
                .into(),
            fanout: Fanout::parse(m.get("fanout").and_then(|v| v.as_str())),
            approvers: parse_str_list(m.get("approvers")),
            deadline_millis: m
                .get("deadline_millis")
                .and_then(|v| v.as_int())
                .unwrap_or(0),
            approvals: parse_str_list(m.get("approvals")),
            denials: parse_str_list(m.get("denials")),
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
    Value::List(xs.iter().map(|s| Value::Str(s.clone())).collect())
}

fn parse_str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Drives the approval actions.
pub struct ApprovalDriver {
    state: Backend,
}

impl ApprovalDriver {
    pub fn new(state: Backend) -> Self {
        Self { state }
    }

    /// Build an approval record's path. `key` arrives from Operation input, so
    /// an illegal path segment is a caller error (returned as `DriverError`),
    /// never a panic.
    fn key_path(key: &str) -> Result<Path, DriverError> {
        Path::parse(&format!("state://kernel/approvals/{key}"))
            .map_err(|e| DriverError::Other(format!("invalid approval key {key:?}: {e}")))
    }

    async fn read_record(&self, path: &Path) -> Result<Option<Record>, DriverError> {
        let v = self
            .state
            .read(path)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(v.as_ref().and_then(Record::from_value))
    }
}

/// Resolve `now` (millis since epoch) from a `now_millis` input field, falling
/// back to the wall clock so live asks expire without an injected clock.
fn now_from(m: &BTreeMap<String, Value>) -> i64 {
    m.get("now_millis")
        .and_then(|v| v.as_int())
        .unwrap_or_else(crate::time::now_millis)
}

#[async_trait]
impl Driver for ApprovalDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = input.as_map().cloned().unwrap_or_default();
        let key = m
            .get("dedup_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if key.is_empty() {
            return Err(DriverError::Other("approval requires a dedup_key".into()));
        }
        let path = Self::key_path(&key)?;
        match method.get() {
            // ask: create-if-absent a pending record carrying the fanout policy,
            // approver set, and deadline. Later asks merge (Cas{None} no-ops).
            0 => {
                let fanout = Fanout::parse(m.get("fanout").and_then(|v| v.as_str()));
                let approvers = parse_str_list(m.get("approvers"));
                let deadline = m
                    .get("deadline_millis")
                    .and_then(|v| v.as_int())
                    .unwrap_or(0)
                    .max(0);
                let record = Record::pending(fanout, approvers, deadline);
                // Only the first ask creates it; later asks no-op (merge).
                let _ = self.state.write_cas(&path, None, record.to_value()).await;
                let current = self.read_record(&path).await?.unwrap_or(record);
                Ok(Outcome::Done(current.to_value()))
            }
            // check: pure read of the current decision, reported as a status
            // string. Reports `expired` once now > deadline while pending.
            1 => {
                let status = match self.read_record(&path).await? {
                    Some(r) => r.effective_status(now_from(&m)).to_string(),
                    None => return Ok(Outcome::Done(Value::Null)),
                };
                Ok(Outcome::Done(Value::Str(status)))
            }
            // respond: an approver records approve/deny; re-resolve under fanout.
            2 => {
                let approver = m
                    .get("approver")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DriverError::Other("respond requires an approver".into()))?
                    .to_string();
                let approve = match m.get("decision").and_then(|v| v.as_str()) {
                    Some("approve") | Some("approved") | Some("yes") => true,
                    Some("deny") | Some("denied") | Some("no") => false,
                    _ => m.get("approve").and_then(|v| v.as_bool()).ok_or_else(|| {
                        DriverError::Other("respond requires decision=approve|deny".into())
                    })?,
                };
                let mut record = self
                    .read_record(&path)
                    .await?
                    .ok_or_else(|| DriverError::Other(format!("no approval for key {key:?}")))?;
                // A lapsed deadline freezes the record at `expired`; late
                // responses do not revive it.
                if record.effective_status(now_from(&m)) == STATUS_EXPIRED {
                    record.status = STATUS_EXPIRED.into();
                    self.state
                        .write_set(&path, record.to_value())
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                    return Ok(Outcome::Done(Value::Str(STATUS_EXPIRED.into())));
                }
                // Once decided (AnyOne first-responder), further responses are
                // ignored — the verdict is stable.
                if !record.is_decided() {
                    record.apply(&approver, approve);
                    self.state
                        .write_set(&path, record.to_value())
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                Ok(Outcome::Done(Value::Str(record.status.clone())))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_state::InMemoryBackend;
    use nexus_types::{IdentityRef, ProcessId};
    use std::sync::Arc;

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn driver() -> ApprovalDriver {
        ApprovalDriver::new(Arc::new(InMemoryBackend::new()))
    }

    fn ask(key: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str(key.into()));
        Value::Map(m)
    }

    async fn check(d: &ApprovalDriver, key: &str, now: Option<i64>) -> String {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str(key.into()));
        if let Some(n) = now {
            m.insert("now_millis".into(), Value::Int(n));
        }
        match d
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap()
        {
            Outcome::Done(Value::Str(s)) => s,
            other => panic!("expected status string, got {other:?}"),
        }
    }

    async fn respond(d: &ApprovalDriver, key: &str, approver: &str, decision: &str) -> String {
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str(key.into()));
        m.insert("approver".into(), Value::Str(approver.into()));
        m.insert("decision".into(), Value::Str(decision.into()));
        match d
            .call(MethodId::new(2), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap()
        {
            Outcome::Done(Value::Str(s)) => s,
            other => panic!("expected status string, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ask_is_idempotent_per_key() {
        let d = driver();
        let a = d
            .call(MethodId::new(0), ask("pay-42"), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        let b = d
            .call(MethodId::new(0), ask("pay-42"), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        assert_eq!(a, b);
        // check observes the pending approval state.
        assert_eq!(check(&d, "pay-42", None).await, "pending");
    }

    #[tokio::test]
    async fn any_one_resolves_on_first_approve() {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str("deploy".into()));
        m.insert("fanout".into(), Value::Str("any_one".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        assert_eq!(check(&d, "deploy", None).await, "pending");
        // First responder decides; bob's later silence is irrelevant.
        assert_eq!(respond(&d, "deploy", "alice", "approve").await, "approved");
        assert_eq!(check(&d, "deploy", None).await, "approved");
    }

    #[tokio::test]
    async fn require_all_needs_every_approver() {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str("wire".into()));
        m.insert("fanout".into(), Value::Str("require_all".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        // One approval is not enough under RequireAll.
        assert_eq!(respond(&d, "wire", "alice", "approve").await, "pending");
        assert_eq!(check(&d, "wire", None).await, "pending");
        // The full quorum resolves it.
        assert_eq!(respond(&d, "wire", "bob", "approve").await, "approved");
        assert_eq!(check(&d, "wire", None).await, "approved");
    }

    #[tokio::test]
    async fn require_all_denied_by_single_veto() {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str("merge".into()));
        m.insert("fanout".into(), Value::Str("require_all".into()));
        m.insert(
            "approvers".into(),
            str_list(&["alice".into(), "bob".into()]),
        );
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        assert_eq!(respond(&d, "merge", "alice", "approve").await, "pending");
        assert_eq!(respond(&d, "merge", "bob", "deny").await, "denied");
        assert_eq!(check(&d, "merge", None).await, "denied");
    }

    #[tokio::test]
    async fn check_reports_expired_past_deadline() {
        let d = driver();
        let mut m = BTreeMap::new();
        m.insert("dedup_key".into(), Value::Str("timed".into()));
        m.insert("deadline_millis".into(), Value::Int(1_000));
        d.call(MethodId::new(0), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        // Before the deadline: still pending.
        assert_eq!(check(&d, "timed", Some(500)).await, "pending");
        // After the deadline: reported expired.
        assert_eq!(check(&d, "timed", Some(2_000)).await, "expired");
        // A late response cannot revive an expired ask.
        let mut r = BTreeMap::new();
        r.insert("dedup_key".into(), Value::Str("timed".into()));
        r.insert("approver".into(), Value::Str("alice".into()));
        r.insert("decision".into(), Value::Str("approve".into()));
        r.insert("now_millis".into(), Value::Int(2_001));
        let out = d
            .call(MethodId::new(2), Value::Map(r), OutputMode::Unary, &ctx())
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("expired".into())));
    }
}
