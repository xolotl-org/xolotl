//! External process runtime: `effect://proc/spawn`,
//! `effect://proc/kill`, `effect://proc/signal`, `effect://proc/status`,
//! `effect://proc/heartbeat`, and the process reconcile loop.
//!
//! `ProcDriver` is the privileged Driver that manages out-of-process external
//! instances. Each action it takes is an Operation (records a Fact)
//! and the live process state is a State Resource at
//! `state://kernel/procs/<id>/status` — there is no kernel special case. In the
//! standard in-process implementation Stdio specs really fork/exec a child
//! process; Grpc/WebSocket/Http specs are connection targets for the endpoint
//! supervisor and are tracked as `starting` until that layer reports readiness.
//!
//! The manager is a supervision routine: it compares
//! the desired set of external installations
//! (`state://kernel/external-installations/*`) against the live process states
//! and drives them toward the desired phase.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, Command};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::Backend;
use xolotl_types::{MethodId, Outcome, OutputMode, Path, ProcSpec, Purity, Transport, Value};
use xolotl_types::{ValueMap, ValueView};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://proc/<method>` Resource with public method
/// `invoke`. All lifecycle mutations are Effectful; `status` is a
/// pure read of external process state.
pub(crate) const PROC_METHODS: &[MethodSpec] = &[
    MethodSpec::new("spawn", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("kill", Purity::Effectful, MethodSpec::UNARY_ASYNC).finalize_allowed(),
    MethodSpec::new("signal", Purity::Effectful, MethodSpec::UNARY_ASYNC).finalize_allowed(),
    MethodSpec::new("status", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external(),
    MethodSpec::new("heartbeat", Purity::Effectful, MethodSpec::UNARY_ASYNC),
];

/// Process lifecycle phases.
pub(crate) const PHASE_STARTING: &str = "starting";
/// External process is ready to serve endpoint traffic.
pub(crate) const PHASE_READY: &str = "ready";
/// External process is draining and rejects new work.
pub(crate) const PHASE_DRAINING: &str = "draining";
/// External process is stopped.
pub(crate) const PHASE_DEAD: &str = "dead";

/// The privileged Driver that manages external processes.
pub(crate) struct ProcDriver {
    state: Backend,
    children: Arc<Mutex<BTreeMap<String, LiveChild>>>,
}

#[derive(Clone)]
struct LiveChild {
    pid: u32,
    child: Arc<tokio::sync::Mutex<Child>>,
}

impl ProcDriver {
    /// Create a process driver backed by the state plane.
    pub(crate) fn new(state: Backend) -> Self {
        Self {
            state,
            children: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Build a process's status path. `id` arrives from Operation input, so an
    /// illegal path segment is a caller error (returned as `DriverError`), never
    /// a panic.
    fn status_path(id: &str) -> Result<Path, DriverError> {
        proc_state_path(id, "status")
    }

    /// Build a process's health path: `last_heartbeat`, `rtt_ms`,
    /// `inflight` live here, updated on each heartbeat.
    fn health_path(id: &str) -> Result<Path, DriverError> {
        proc_state_path(id, "health")
    }

    fn status_value(
        phase: &str,
        restarts: i64,
        transport: Option<&Transport>,
        pid: Option<u32>,
        exit_code: Option<i32>,
    ) -> Value {
        let mut m = BTreeMap::new();
        m.insert("phase".into(), Value::string(phase.into()));
        m.insert("restarts".into(), Value::integer(restarts));
        m.insert(
            "started_at".into(),
            Value::integer(xolotl_kernel::now_millis()),
        );
        if let Some(transport) = transport {
            m.insert(
                "transport".into(),
                Value::string(transport_name(transport).into()),
            );
        }
        if let Some(pid) = pid {
            m.insert("pid".into(), Value::integer(pid as i64));
        }
        if let Some(exit_code) = exit_code {
            m.insert("exit_code".into(), Value::integer(exit_code as i64));
        }
        Value::map(m)
    }

    async fn read_status(&self, id: &str) -> Result<Option<Value>, DriverError> {
        let path = Self::status_path(id)?;
        self.state
            .read(&path)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))
    }

    async fn write_status(&self, id: &str, status: Value) -> Result<DriverOutput, DriverError> {
        self.state
            .write_set(&Self::status_path(id)?, status.clone())
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(DriverOutput::new(Outcome::Done(status)))
    }

    fn live_child(&self, id: &str) -> Option<LiveChild> {
        self.children.lock().get(id).cloned()
    }

    async fn refresh_child_status(&self, id: &str) -> Result<Option<Value>, DriverError> {
        let Some(live) = self.live_child(id) else {
            return Ok(None);
        };
        let exit = {
            let mut child = live.child.lock().await;
            child
                .try_wait()
                .map_err(|e| DriverError::Other(format!("proc status failed for {id:?}: {e}")))?
        };
        let Some(exit) = exit else {
            return Ok(None);
        };
        let restarts = match self.read_status(id).await? {
            Some(status) => stored_proc_status(&status)?.restarts,
            None => 0,
        };
        self.children.lock().remove(id);
        let status = Self::status_value(PHASE_DEAD, restarts, None, Some(live.pid), exit.code());
        self.state
            .write_set(&Self::status_path(id)?, status.clone())
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(Some(status))
    }

    async fn ensure_not_running(&self, id: &str) -> Result<(), DriverError> {
        if self.refresh_child_status(id).await?.is_none() && self.live_child(id).is_some() {
            return Err(DriverError::Other(format!(
                "proc {id:?} is already running"
            )));
        }
        if let Some(status) = self.read_status(id).await? {
            let status = stored_proc_status(&status)?;
            if matches!(status.phase, PHASE_STARTING | PHASE_READY | PHASE_DRAINING) {
                return Err(DriverError::Other(format!(
                    "proc {id:?} is already in phase {:?}",
                    status.phase
                )));
            }
        }
        Ok(())
    }

    fn spawn_stdio_child(&self, spec: &ProcSpec) -> Result<(u32, LiveChild), DriverError> {
        let argv = spec.command.as_ref().ok_or_else(|| {
            DriverError::Other("stdio proc.spawn requires ProcSpec.command argv".into())
        })?;
        let program = argv
            .first()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DriverError::Other("stdio proc.spawn command argv is empty".into()))?;
        let mut cmd = Command::new(program);
        cmd.args(argv.iter().skip(1));
        cmd.envs(spec.env.iter());
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| DriverError::Other(format!("spawn {program:?} failed: {e}")))?;
        let pid = child
            .id()
            .ok_or_else(|| DriverError::Other("spawned child did not expose a pid".into()))?;
        let live = LiveChild {
            pid,
            child: Arc::new(tokio::sync::Mutex::new(child)),
        };
        Ok((pid, live))
    }

    async fn kill_child(&self, id: &str) -> Result<Option<u32>, DriverError> {
        let live = self.children.lock().remove(id);
        let Some(live) = live else {
            return Ok(None);
        };
        let mut child = live.child.lock().await;
        child
            .kill()
            .await
            .map_err(|e| DriverError::Other(format!("kill proc {id:?} failed: {e}")))?;
        Ok(Some(live.pid))
    }
}

#[async_trait]
impl Driver for ProcDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        match method.get() {
            // spawn: bring up (or connect to) the external process. Stdio
            // specs fork/exec here; endpoint transports are tracked as
            // Starting until EndpointSupervisor reports readiness.
            0 => {
                let restarts = match input.view() {
                    ValueView::Map(m) => optional_non_negative_int(m, "restarts", 0)?,
                    _ => {
                        return Err(DriverError::InvalidInput(
                            "proc.spawn input must be a ProcSpec map".into(),
                        ));
                    }
                };
                let spec = parse_proc_spec(input)?;
                self.ensure_not_running(&spec.id).await?;
                let pid = match &spec.transport {
                    Transport::Stdio { .. } => {
                        let (pid, live) = self.spawn_stdio_child(&spec)?;
                        self.children.lock().insert(spec.id.clone(), live);
                        Some(pid)
                    }
                    _ => None,
                };
                let status =
                    Self::status_value(PHASE_STARTING, restarts, Some(&spec.transport), pid, None);
                self.write_status(&spec.id, status).await
            }
            // kill: drain then mark dead.
            1 => {
                let m = crate::input::map(input, "proc.kill")?;
                let id = required_id(&m)?;
                let stored_status = self.read_status(&id).await?;
                let restarts = match stored_status.as_ref() {
                    Some(status) => stored_proc_status(status)?.restarts,
                    None => 0,
                };
                let had_status = stored_status.is_some();
                let pid = self.kill_child(&id).await?;
                if pid.is_none() && !had_status {
                    return Err(DriverError::Other(format!("unknown proc id {id:?}")));
                }
                let status = Self::status_value(PHASE_DEAD, restarts, None, pid, None);
                self.write_status(&id, status).await
            }
            // signal: deliver a signal to a managed Stdio child.
            2 => {
                let m = crate::input::map(input, "proc.signal")?;
                let id = required_id(&m)?;
                let sig = optional_signal(&m)?.to_string();
                let live = self.live_child(&id).ok_or_else(|| {
                    DriverError::Other(format!("proc {id:?} has no managed child to signal"))
                })?;
                send_signal(live.pid, &sig).await?;
                Ok(DriverOutput::new(Outcome::Done(Value::string(sig))))
            }
            // status: read the current lifecycle state.
            3 => {
                let m = crate::input::map(input, "proc.status")?;
                let id = required_id(&m)?;
                if let Some(status) = self.refresh_child_status(&id).await? {
                    return Ok(DriverOutput::new(Outcome::Done(status)));
                }
                match self.read_status(&id).await? {
                    Some(status) => {
                        stored_proc_status(&status)?;
                        Ok(DriverOutput::new(Outcome::Done(status)))
                    }
                    None => Ok(DriverOutput::new(Outcome::Done(Value::null()))),
                }
            }
            // heartbeat: record liveness to the health path. Input may
            // carry `rtt_ms` / `inflight`; we stamp `last_heartbeat` from the
            // clock so a supervisor can detect a stalled process.
            4 => {
                let m = crate::input::map(input, "proc.heartbeat")?;
                let id = required_id(&m)?;
                let rtt = optional_non_negative_int(&m, "rtt_ms", 0)?;
                let inflight = optional_non_negative_int(&m, "inflight", 0)?;
                let promotion = match self.read_status(&id).await? {
                    Some(status) => {
                        let status = stored_proc_status(&status)?;
                        if status.phase == PHASE_STARTING {
                            Some((status.restarts, status.pid))
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let mut health = BTreeMap::new();
                health.insert(
                    "last_heartbeat".into(),
                    Value::integer(xolotl_kernel::now_millis()),
                );
                health.insert("rtt_ms".into(), Value::integer(rtt));
                health.insert("inflight".into(), Value::integer(inflight));
                self.state
                    .write_set(&Self::health_path(&id)?, Value::map(health))
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                if let Some((restarts, pid)) = promotion {
                    let promoted = Self::status_value(PHASE_READY, restarts, None, pid, None);
                    self.state
                        .write_set(&Self::status_path(&id)?, promoted)
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                Ok(DriverOutput::new(Outcome::Done(Value::boolean(true))))
            }
            _ => Err(DriverError::Other(format!(
                "unknown proc method {}",
                method.get()
            ))),
        }
    }
}

struct StoredProcStatus<'a> {
    phase: &'a str,
    restarts: i64,
    pid: Option<u32>,
}

fn parse_proc_spec(input: Value) -> Result<ProcSpec, DriverError> {
    let json = serde_json::to_value(&input)
        .map_err(|e| DriverError::Other(format!("proc spec serialization failed: {e}")))?;
    let spec: ProcSpec = serde_json::from_value(json)
        .map_err(|e| DriverError::Other(format!("proc.spawn requires ProcSpec input: {e}")))?;
    validate_proc_id(&spec.id)?;
    match &spec.transport {
        Transport::Stdio { command, args } => {
            let argv = spec.command.as_ref().ok_or_else(|| {
                DriverError::Other("stdio proc.spawn requires ProcSpec.command argv".into())
            })?;
            if argv.is_empty() {
                return Err(DriverError::Other(
                    "stdio proc.spawn requires non-empty ProcSpec.command argv".into(),
                ));
            }
            let Some(program) = command.as_ref().filter(|program| !program.is_empty()) else {
                return Err(DriverError::Other(
                    "stdio proc.spawn requires Transport::Stdio.command".into(),
                ));
            };
            let transport_argv = std::iter::once(program)
                .chain(args.iter())
                .cloned()
                .collect::<Vec<_>>();
            if argv != &transport_argv {
                return Err(DriverError::Other(
                    "ProcSpec.command must match Transport::Stdio command/args".into(),
                ));
            }
        }
        _ => {
            if spec.command.is_some() {
                return Err(DriverError::Other(
                    "non-stdio proc.spawn must not carry ProcSpec.command argv".into(),
                ));
            }
            if !spec.env.is_empty() || spec.cwd.is_some() {
                return Err(DriverError::Other(
                    "non-stdio proc.spawn must not carry env or cwd".into(),
                ));
            }
        }
    }
    Ok(spec)
}

fn proc_state_path(id: &str, leaf: &str) -> Result<Path, DriverError> {
    validate_proc_id(id)?;
    Path::try_new("state")
        .and_then(|path| path.try_push("kernel"))
        .and_then(|path| path.try_push("procs"))
        .and_then(|path| path.try_push_literal(id))
        .and_then(|path| path.try_push_literal(leaf))
        .map_err(|e| DriverError::Other(format!("invalid proc id {id:?}: {e}")))
}

fn validate_proc_id(id: &str) -> Result<(), DriverError> {
    Path::try_new("state")
        .and_then(|path| path.try_push_literal(id))
        .map(|_| ())
        .map_err(|e| DriverError::Other(format!("invalid proc id {id:?}: {e}")))
}

fn required_id(m: &ValueMap) -> Result<String, DriverError> {
    let id = m
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| DriverError::Other("proc op requires id".into()))?;
    validate_proc_id(id)?;
    Ok(id.to_string())
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
            "proc {field} must be non-negative"
        ))),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "proc {field} must be an integer"
        ))),
    }
}

fn stored_proc_status(value: &Value) -> Result<StoredProcStatus<'_>, DriverError> {
    let Some(m) = value.as_map() else {
        return Err(DriverError::Other(
            "malformed proc status: not a map".into(),
        ));
    };
    let phase = match m.get("phase").map(Value::view) {
        Some(ValueView::Str(phase))
            if matches!(
                phase,
                PHASE_STARTING | PHASE_READY | PHASE_DRAINING | PHASE_DEAD
            ) =>
        {
            phase
        }
        Some(ValueView::Str(phase)) => {
            return Err(DriverError::Other(format!(
                "malformed proc status: unknown phase {phase:?}"
            )));
        }
        Some(_) => {
            return Err(DriverError::Other(
                "malformed proc status: phase must be a string".into(),
            ));
        }
        None => {
            return Err(DriverError::Other(
                "malformed proc status: missing phase".into(),
            ));
        }
    };
    let restarts = required_stored_non_negative_int(m, "restarts")?;
    let pid = optional_stored_pid(m)?;
    if let Some(value) = m.get("transport")
        && value.as_str().is_none()
    {
        return Err(DriverError::Other(
            "malformed proc status: transport must be a string".into(),
        ));
    }
    if let Some(value) = m.get("exit_code")
        && value.as_int().is_none()
    {
        return Err(DriverError::Other(
            "malformed proc status: exit_code must be an integer".into(),
        ));
    }
    Ok(StoredProcStatus {
        phase,
        restarts,
        pid,
    })
}

fn required_stored_non_negative_int(m: &ValueMap, field: &'static str) -> Result<i64, DriverError> {
    match m.get(field).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(DriverError::Other(format!(
            "malformed proc status: {field} must be non-negative"
        ))),
        Some(_) => Err(DriverError::Other(format!(
            "malformed proc status: {field} must be an integer"
        ))),
        None => Err(DriverError::Other(format!(
            "malformed proc status: missing {field}"
        ))),
    }
}

fn optional_stored_pid(m: &ValueMap) -> Result<Option<u32>, DriverError> {
    match m.get("pid").map(Value::view) {
        None => Ok(None),
        Some(ValueView::Int(pid)) if pid > 0 => u32::try_from(pid).map(Some).map_err(|_error| {
            DriverError::Other("malformed proc status: pid is out of range".into())
        }),
        Some(ValueView::Int(_)) => Err(DriverError::Other(
            "malformed proc status: pid must be positive".into(),
        )),
        Some(_) => Err(DriverError::Other(
            "malformed proc status: pid must be an integer".into(),
        )),
    }
}

fn optional_signal(m: &ValueMap) -> Result<&str, DriverError> {
    match m.get("signal").map(Value::view) {
        None => Ok("TERM"),
        Some(ValueView::Str(signal)) if !signal.is_empty() => Ok(signal),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(
            "proc signal must not be empty".into(),
        )),
        Some(_) => Err(DriverError::InvalidInput(
            "proc signal must be a string".into(),
        )),
    }
}

fn transport_name(t: &Transport) -> &'static str {
    match t {
        Transport::InProcess => "in_process",
        Transport::Grpc { .. } => "grpc",
        Transport::Stdio { .. } => "stdio",
        Transport::WebSocket { .. } => "websocket",
        Transport::Http { .. } => "http",
    }
}

#[cfg(unix)]
async fn send_signal(pid: u32, sig: &str) -> Result<(), DriverError> {
    if sig.is_empty() || !sig.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(DriverError::Other(format!("invalid signal name {sig:?}")));
    }
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .await
        .map_err(|e| DriverError::Other(format!("signal {sig} to pid {pid} failed: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(DriverError::Other(format!(
            "signal {sig} to pid {pid} exited with {status}"
        )))
    }
}

#[cfg(not(unix))]
async fn send_signal(_pid: u32, sig: &str) -> Result<(), DriverError> {
    Err(DriverError::Other(format!(
        "signal {sig:?} is unsupported on this platform"
    )))
}

/// Reconcile the desired external process set against live process states.
#[cfg(test)]
fn reconcile(desired_ids: &[String], live: &BTreeMap<String, String>) -> Vec<String> {
    desired_ids
        .iter()
        .filter(|id| match live.get(*id) {
            None => true,                       // not started yet
            Some(phase) => phase == PHASE_DEAD, // crashed → restart (RestartPolicy)
        })
        .cloned()
        .collect()
}

/// What a restart policy decides for a crashed process.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuperviseDecision {
    /// Restart now (no delay).
    Restart,
    /// Restart after `delay_ms` (backoff).
    RestartAfter {
        /// Delay before attempting the restart.
        delay_ms: u64,
    },
    /// Stop at Dead and alarm — the crash budget is exhausted.
    GiveUp,
}

/// Evaluate a restart policy for a crashed process.
#[cfg(test)]
fn supervise(
    policy: &xolotl_types::external::RestartPolicy,
    failures_in_window: u32,
    attempt: u32,
) -> SuperviseDecision {
    use xolotl_types::external::{Backoff, RestartPolicy};
    match policy {
        RestartPolicy::Never => SuperviseDecision::GiveUp,
        RestartPolicy::OnFailure { max, .. } => {
            if failures_in_window > *max {
                // Exceeded the crash budget in the window → stop + alarm.
                SuperviseDecision::GiveUp
            } else {
                SuperviseDecision::Restart
            }
        }
        RestartPolicy::Always { backoff } => {
            let delay_ms = match backoff {
                Backoff::Fixed { ms } => *ms,
                Backoff::Exp {
                    base_ms, cap_ms, ..
                } => {
                    // base * 2^attempt, capped. Jitter is applied by the caller
                    // (it needs a clock/RNG); the policy yields the deterministic
                    // bound here.
                    let shifted = base_ms.saturating_mul(1u64 << attempt.min(20));
                    shifted.min(*cap_ms)
                }
            };
            if delay_ms == 0 {
                SuperviseDecision::Restart
            } else {
                SuperviseDecision::RestartAfter { delay_ms }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{IdentityRef, ProcessId};

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn id_input(id: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("id".into(), Value::string(id.into()));
        Value::map(m)
    }

    fn stdio_spec_input(id: &str, command: Vec<&str>) -> anyhow::Result<Value> {
        let Some((program, args)) = command.split_first() else {
            bail!("stdio command must not be empty");
        };
        let spec = ProcSpec {
            id: id.into(),
            transport: Transport::Stdio {
                command: Some((*program).into()),
                args: args.iter().map(|arg| (*arg).into()).collect(),
            },
            command: Some(command.into_iter().map(str::to_string).collect()),
            env: BTreeMap::new(),
            cwd: None,
            restart: xolotl_types::RestartPolicy::Never,
        };
        Ok(serde_json::from_value(serde_json::to_value(spec)?)?)
    }

    fn websocket_spec_input(id: &str) -> anyhow::Result<Value> {
        let spec = ProcSpec {
            id: id.into(),
            transport: Transport::WebSocket {
                endpoint: Some("wss://example.test/ext".into()),
            },
            command: None,
            env: BTreeMap::new(),
            cwd: None,
            restart: xolotl_types::RestartPolicy::Never,
        };
        Ok(serde_json::from_value(serde_json::to_value(spec)?)?)
    }

    #[tokio::test]
    async fn spawn_requires_proc_spec_not_id_shorthand() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let out = d
            .call(
                MethodId::new(0),
                id_input("id-only-ext"),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "id shorthand spawn was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn spawn_rejects_inconsistent_stdio_argv() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let spec = ProcSpec {
            id: "ext-argv".into(),
            transport: Transport::Stdio {
                command: Some("/bin/sh".into()),
                args: vec!["-c".into(), "sleep 1".into()],
            },
            command: Some(vec!["/bin/echo".into(), "mismatch".into()]),
            env: BTreeMap::new(),
            cwd: None,
            restart: xolotl_types::RestartPolicy::Never,
        };
        let input = serde_json::from_value(serde_json::to_value(spec)?)?;

        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("must match")),
            "unexpected inconsistent argv result: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn spawn_rejects_command_fields_for_endpoint_transports() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let spec = ProcSpec {
            id: "ext-ws".into(),
            transport: Transport::WebSocket {
                endpoint: Some("wss://example.test/ext".into()),
            },
            command: Some(vec!["/bin/echo".into()]),
            env: BTreeMap::new(),
            cwd: None,
            restart: xolotl_types::RestartPolicy::Never,
        };
        let input = serde_json::from_value(serde_json::to_value(spec)?)?;

        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("non-stdio")),
            "unexpected endpoint transport command result: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn spawn_rejects_proc_id_path_delimiters() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let spec = ProcSpec {
            id: "ext/bad".into(),
            transport: Transport::WebSocket {
                endpoint: Some("wss://example.test/ext".into()),
            },
            command: None,
            env: BTreeMap::new(),
            cwd: None,
            restart: xolotl_types::RestartPolicy::Never,
        };
        let input = serde_json::from_value(serde_json::to_value(spec)?)?;

        let out = d
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("invalid proc id")),
            "unexpected invalid id result: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn signal_rejects_non_string_signal() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let mut m = BTreeMap::new();
        m.insert("id".into(), Value::string("ext-sig".into()));
        m.insert("signal".into(), Value::integer(15));

        let out = d
            .call(MethodId::new(2), Value::map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(
            matches!(out, Err(DriverError::InvalidInput(ref message)) if message.contains("signal")),
            "unexpected invalid signal result: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stdio_spawn_then_status_reports_starting_with_pid() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let out = d
            .call(
                MethodId::new(0),
                stdio_spec_input("ext-a", vec!["/bin/sh", "-c", "sleep 1"])?,
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let phase = m.get("phase").and_then(|v| v.as_str());
                ensure!(
                    phase == Some(PHASE_STARTING),
                    "expected starting phase, got {phase:?}"
                );
                let transport = m.get("transport").and_then(|v| v.as_str());
                ensure!(
                    transport == Some("stdio"),
                    "expected stdio transport, got {transport:?}"
                );
                ensure!(
                    m.get("pid")
                        .and_then(Value::as_int)
                        .is_some_and(|pid| pid > 0),
                    "expected positive pid, got {:?}",
                    m.get("pid")
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        let out = d
            .call(
                MethodId::new(3),
                id_input("ext-a"),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let phase = m.get("phase").and_then(|v| v.as_str());
                ensure!(
                    phase == Some(PHASE_STARTING),
                    "expected starting phase, got {phase:?}"
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        d.call(
            MethodId::new(1),
            id_input("ext-a"),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_promotes_starting_child_to_ready() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        d.call(
            MethodId::new(0),
            stdio_spec_input("ext-ready", vec!["/bin/sh", "-c", "sleep 1"])?,
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
        let mut hb = BTreeMap::new();
        hb.insert("id".into(), Value::string("ext-ready".into()));
        d.call(MethodId::new(4), Value::map(hb), OutputMode::Unary, &ctx())
            .await?;
        let out = d
            .call(
                MethodId::new(3),
                id_input("ext-ready"),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let phase = m.get("phase").and_then(|v| v.as_str());
                ensure!(
                    phase == Some(PHASE_READY),
                    "expected ready phase, got {phase:?}"
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        d.call(
            MethodId::new(1),
            id_input("ext-ready"),
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn kill_marks_dead() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        d.call(
            MethodId::new(0),
            stdio_spec_input("ext-b", vec!["/bin/sh", "-c", "sleep 10"])?,
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
        let out = d
            .call(
                MethodId::new(1),
                id_input("ext-b"),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let phase = m.get("phase").and_then(|v| v.as_str());
                ensure!(
                    phase == Some(PHASE_DEAD),
                    "expected dead phase, got {phase:?}"
                );
                ensure!(
                    m.get("pid")
                        .and_then(Value::as_int)
                        .is_some_and(|pid| pid > 0),
                    "expected positive pid, got {:?}",
                    m.get("pid")
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn kill_preserves_stored_restart_count() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state.clone());
        let mut status = BTreeMap::new();
        status.insert("phase".into(), Value::string(PHASE_READY.into()));
        status.insert("restarts".into(), Value::integer(4));
        state
            .write_set(
                &ProcDriver::status_path("ext-restarts")?,
                Value::map(status),
            )
            .await?;

        let out = d
            .call(
                MethodId::new(1),
                id_input("ext-restarts"),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                ensure!(
                    m.get("phase") == Some(&Value::string(PHASE_DEAD.into())),
                    "expected dead phase, got {:?}",
                    m.get("phase")
                );
                ensure!(
                    m.get("restarts") == Some(&Value::integer(4)),
                    "kill reset restart count: {:?}",
                    m.get("restarts")
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn status_terminalizes_exited_stdio_child() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        d.call(
            MethodId::new(0),
            stdio_spec_input("ext-exit", vec!["/bin/sh", "-c", "exit 7"])?,
            OutputMode::Unary,
            &ctx(),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let out = d
            .call(
                MethodId::new(3),
                id_input("ext-exit"),
                OutputMode::Unary,
                &ctx(),
            )
            .await?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let phase = m.get("phase").and_then(|v| v.as_str());
                ensure!(
                    phase == Some(PHASE_DEAD),
                    "expected dead phase, got {phase:?}"
                );
                ensure!(
                    m.get("exit_code") == Some(&Value::integer(7)),
                    "expected exit code 7, got {:?}",
                    m.get("exit_code")
                );
            }
            other => bail!("expected status map, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn reconcile_restarts_absent_and_dead() {
        let desired = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut live = BTreeMap::new();
        live.insert("a".into(), PHASE_READY.to_string());
        live.insert("b".into(), PHASE_DEAD.to_string());
        // c is absent.
        let need = reconcile(&desired, &live);
        assert_eq!(need, vec!["b".to_string(), "c".to_string()]);
    }

    #[tokio::test]
    async fn heartbeat_writes_health() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state.clone());
        let mut m = BTreeMap::new();
        m.insert("id".into(), Value::string("ext-h".into()));
        m.insert("rtt_ms".into(), Value::integer(12));
        m.insert("inflight".into(), Value::integer(3));
        d.call(MethodId::new(4), Value::map(m), OutputMode::Unary, &ctx())
            .await?;
        let health_path = xolotl_types::Path::parse("state://kernel/procs/ext-h/health")
            .context("parse health path")?;
        let health = state
            .read(&health_path)
            .await?
            .context("health record missing")?;
        let hm = health.as_map().context("health record is not a map")?;
        ensure!(
            hm.get("rtt_ms") == Some(&Value::integer(12)),
            "unexpected rtt_ms: {:?}",
            hm.get("rtt_ms")
        );
        ensure!(
            hm.get("inflight") == Some(&Value::integer(3)),
            "unexpected inflight: {:?}",
            hm.get("inflight")
        );
        ensure!(
            hm.get("last_heartbeat").and_then(Value::as_int).is_some(),
            "missing last heartbeat: {:?}",
            hm.get("last_heartbeat")
        );
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_invalid_id_and_metrics() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state);
        let mut bad_id = BTreeMap::new();
        bad_id.insert("id".into(), Value::string("ext/h".into()));
        let out = d
            .call(
                MethodId::new(4),
                Value::map(bad_id),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "heartbeat accepted id with path delimiter");

        let mut bad_metric = BTreeMap::new();
        bad_metric.insert("id".into(), Value::string("ext-h".into()));
        bad_metric.insert("rtt_ms".into(), Value::integer(-1));
        let out = d
            .call(
                MethodId::new(4),
                Value::map(bad_metric),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "heartbeat accepted negative rtt_ms");
        Ok(())
    }

    #[tokio::test]
    async fn status_rejects_malformed_persisted_state() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state.clone());
        let mut status = BTreeMap::new();
        status.insert("phase".into(), Value::string(PHASE_STARTING.into()));
        status.insert("restarts".into(), Value::string("bad".into()));
        state
            .write_set(&ProcDriver::status_path("ext-corrupt")?, Value::map(status))
            .await?;

        let out = d
            .call(
                MethodId::new(3),
                id_input("ext-corrupt"),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("malformed proc status")),
            "status accepted malformed persisted state: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_rejects_malformed_status_without_writing_health() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state.clone());
        let mut status = BTreeMap::new();
        status.insert("phase".into(), Value::string(PHASE_STARTING.into()));
        status.insert("restarts".into(), Value::string("bad".into()));
        state
            .write_set(
                &ProcDriver::status_path("ext-corrupt-hb")?,
                Value::map(status),
            )
            .await?;

        let out = d
            .call(
                MethodId::new(4),
                id_input("ext-corrupt-hb"),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("malformed proc status")),
            "heartbeat accepted malformed persisted status: {out:?}"
        );
        let health_path = xolotl_types::Path::parse("state://kernel/procs/ext-corrupt-hb/health")
            .context("parse health path")?;
        ensure!(
            state.read(&health_path).await?.is_none(),
            "heartbeat wrote health for malformed proc status"
        );
        Ok(())
    }

    #[tokio::test]
    async fn spawn_rejects_malformed_persisted_status() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = ProcDriver::new(state.clone());
        let mut status = BTreeMap::new();
        status.insert("phase".into(), Value::integer(1));
        status.insert("restarts".into(), Value::integer(0));
        state
            .write_set(
                &ProcDriver::status_path("ext-corrupt-spawn")?,
                Value::map(status),
            )
            .await?;

        let out = d
            .call(
                MethodId::new(0),
                websocket_spec_input("ext-corrupt-spawn")?,
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(
            matches!(out, Err(DriverError::Other(ref message)) if message.contains("malformed proc status")),
            "spawn accepted malformed persisted status: {out:?}"
        );
        Ok(())
    }

    #[test]
    fn supervise_on_failure_gives_up_past_budget() {
        use xolotl_types::external::RestartPolicy;
        let policy = RestartPolicy::OnFailure {
            max: 3,
            window_ms: 60_000,
        };
        // Within budget → restart.
        assert_eq!(supervise(&policy, 2, 1), SuperviseDecision::Restart);
        assert_eq!(supervise(&policy, 3, 2), SuperviseDecision::Restart);
        // Exceeds budget → give up + alarm.
        assert_eq!(supervise(&policy, 4, 3), SuperviseDecision::GiveUp);
    }

    #[test]
    fn supervise_never_gives_up_immediately() {
        use xolotl_types::external::RestartPolicy;
        assert_eq!(
            supervise(&RestartPolicy::Never, 0, 0),
            SuperviseDecision::GiveUp
        );
    }

    #[test]
    fn supervise_always_applies_exponential_backoff() {
        use xolotl_types::external::{Backoff, RestartPolicy};
        let policy = RestartPolicy::Always {
            backoff: Backoff::Exp {
                base_ms: 100,
                cap_ms: 1000,
                jitter: false,
            },
        };
        // 100 * 2^0 = 100, 2^1=200, 2^4=1600 capped to 1000.
        assert_eq!(
            supervise(&policy, 1, 0),
            SuperviseDecision::RestartAfter { delay_ms: 100 }
        );
        assert_eq!(
            supervise(&policy, 2, 1),
            SuperviseDecision::RestartAfter { delay_ms: 200 }
        );
        assert_eq!(
            supervise(&policy, 5, 4),
            SuperviseDecision::RestartAfter { delay_ms: 1000 }
        );
    }
}
