//! Shell-free `effect://terminal/run`, authorized by Kernel grants and host allow/deny lists.
//! Cancellation is not rollback: a spawned command may already have performed effects.
//! The host owns admission and cleanup through [`TerminalRuntime`], independently of Proc State.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, OperationId, Outcome, OutputMode, Purity, Value};
use xolotl_types::{ValueMap, ValueView};

const DEFAULT_TERMINAL_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const HARD_TERMINAL_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TERMINAL_TIMEOUT_MS: u64 = 30_000;
const HARD_TERMINAL_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Method names for `effect://terminal/run`; the public method is `invoke`
/// after standard installation.
pub(crate) const TERMINAL_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "run",
    xolotl_types::MethodAuthority::Perform,
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Commands always refused regardless of the allowlist.
/// These have no safe argv form through this one-shot, shell-free runner.
pub(crate) const DEFAULT_DENYLIST: &[&str] =
    &["sudo", "su", "doas", "chroot", "nc", "ncat", "telnet"];

/// Host-owned admission and cleanup domain shared by all installed Terminal drivers.
///
/// The default admits 16 concurrent calls. A slot charges one supervisor, its direct
/// child, and two bounded output buffers (default 1 MiB each, maximum 16 MiB each;
/// these are not RSS limits). Full admission rejects immediately before spawning.
/// Slots remain charged through pipe closure and direct-child reaping, even when
/// callers disappear. One supervisor polls both pipes and the child; there are no
/// detached reader tasks. The call deadline covers child exit AND pipe EOF.
/// Timeout results are delivered only after cleanup, so cleanup can exceed that deadline.
/// Every invocation must supply its originating typed OperationId before spawning.
/// Admission and spawn rejection are known failures. After successful spawn, timeout,
/// I/O failure, or close returns OutcomeUnknown with that original identity: killing
/// and reaping cannot prove absence of command effects. Handled errors still require
/// reconciliation and never grant replay permission (NonIdempotentEffect).
///
/// [`Self::close`] permanently rejects admission and signals cancellation of accepted
/// calls. [`Self::shutdown`] also waits for their cleanup; concurrent or interrupted
/// shutdown waiters do not lose ownership. Hosts must keep Tokio running until it
/// completes. Cancellation, deadline, and close drop pipes, kill and reap the direct
/// child; `kill_on_drop` is only a runtime-teardown fallback, not a reaping guarantee.
/// Descendants are not tracked or killed. External effects are never rolled back.
/// OS reaping failures retain capacity and leave shutdown incomplete until reaping
/// succeeds; retries back off to one second. The first kill and wait failures are
/// appended to the call error if cleanup eventually completes. There is no repeated
/// error logging; a cancelled caller cannot receive these diagnostics.
#[derive(Clone)]
pub struct TerminalRuntime {
    inner: Arc<TerminalRuntimeInner>,
}

struct TerminalRuntimeInner {
    admission: parking_lot::Mutex<bool>,
    slots: Arc<Semaphore>,
    closed: watch::Sender<bool>,
    active: watch::Sender<usize>,
    #[cfg(test)]
    cleanup_gate: parking_lot::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

impl Default for TerminalRuntime {
    fn default() -> Self {
        Self::new(NonZeroUsize::MIN.saturating_add(15))
    }
}

impl TerminalRuntime {
    /// Choose a finite host-wide concurrent-call limit. Exhaustion rejects, not queues.
    ///
    /// # Panics
    /// Panics if the limit exceeds [`Semaphore::MAX_PERMITS`].
    pub fn new(max_concurrent_calls: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(TerminalRuntimeInner {
                admission: parking_lot::Mutex::new(false),
                slots: Arc::new(Semaphore::new(max_concurrent_calls.get())),
                closed: watch::channel(false).0,
                active: watch::channel(0).0,
                #[cfg(test)]
                cleanup_gate: parking_lot::Mutex::new(None),
            }),
        }
    }

    /// Reject new calls and cancel accepted calls. Idempotent and nonblocking.
    pub fn close(&self) {
        let mut closed = self.inner.admission.lock();
        *closed = true;
        self.inner.closed.send_replace(true);
    }

    /// Close admission, then wait for all direct children and supervisors to finish.
    pub async fn shutdown(&self) {
        self.close();
        let mut active = self.inner.active.subscribe();
        let _finished = active.wait_for(|count| *count == 0).await;
    }

    fn admit(&self) -> Result<TerminalSlot, DriverError> {
        let closed = self.inner.admission.lock();
        if *closed {
            return Err(DriverError::Other("terminal runtime is closed".into()));
        }
        let permit = self
            .inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_error| {
                DriverError::Other("terminal concurrent call capacity exhausted".into())
            })?;
        self.inner.active.send_modify(|count| *count += 1);
        Ok(TerminalSlot {
            inner: self.inner.clone(),
            permit: Some(permit),
        })
    }

    async fn run(
        &self,
        operation_id: OperationId,
        cmd: String,
        args: Vec<String>,
        max_output_bytes: usize,
        timeout_ms: u64,
    ) -> Result<TerminalOutput, DriverError> {
        let slot = self.admit()?;
        let closed = self.inner.closed.subscribe();
        let (mut result, received) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let request = TerminalRequest {
            operation_id,
            cmd,
            args,
            max_output_bytes,
            timeout_ms,
            deadline,
        };
        tokio::spawn(async move {
            let output = supervise_terminal(request, closed, &mut result, &slot).await;
            drop(slot);
            let _sent = result.send(output);
        });
        received
            .await
            .map_err(|_error| DriverError::OutcomeUnknown {
                operation_id: operation_id.to_string(),
                reason: "terminal supervisor stopped without a spawn verdict".into(),
            })?
    }
}

struct TerminalSlot {
    inner: Arc<TerminalRuntimeInner>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for TerminalSlot {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.inner.active.send_modify(|count| *count -= 1);
    }
}

/// Drives shell-free commands. Host policy, not caller-provided approval, gates spawn.
pub(crate) struct TerminalDriver {
    allowlist: Vec<String>,
    denylist: Vec<String>,
    runtime: TerminalRuntime,
}

impl TerminalDriver {
    pub(crate) fn new(allowlist: Vec<String>, runtime: TerminalRuntime) -> Self {
        Self {
            allowlist,
            denylist: DEFAULT_DENYLIST
                .iter()
                .map(|name| name.to_string())
                .collect(),
            runtime,
        }
    }

    pub(crate) fn with_denylist(mut self, denylist: Vec<String>) -> Self {
        extend_unique(&mut self.denylist, denylist);
        self
    }

    fn gate(&self, cmd: &str) -> Result<(), DriverError> {
        if self
            .denylist
            .iter()
            .any(|listed| command_matches(cmd, listed))
        {
            return Err(DriverError::Other(format!("command is denylisted: {cmd}")));
        }
        if !self.allowlist.iter().any(|listed| listed == cmd) {
            return Err(DriverError::Other(format!(
                "command not on allowlist: {cmd}"
            )));
        }
        Ok(())
    }
}

fn extend_unique(target: &mut Vec<String>, items: Vec<String>) {
    target.extend(items);
    target.sort();
    target.dedup();
}

fn command_matches(cmd: &str, listed: &str) -> bool {
    if cmd == listed {
        return true;
    }
    match (command_basename(cmd), command_basename(listed)) {
        (Some(cmd_base), Some(listed_base)) => cmd_base == listed_base,
        _ => false,
    }
}

fn command_basename(cmd: &str) -> Option<&str> {
    std::path::Path::new(cmd).file_name()?.to_str()
}

#[async_trait]
impl Driver for TerminalDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let m = crate::input::map(input, "terminal.run")?;
        if m.get("approved").is_some() {
            return Err(DriverError::InvalidInput(
                "terminal.run no longer accepts `approved`; command authorization is host policy"
                    .into(),
            ));
        }
        let cmd = m
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("terminal.run requires `command`".into()))?
            .to_string();
        self.gate(&cmd)?;
        let max_output_bytes = optional_bounded_usize(
            &m,
            "max_output_bytes",
            DEFAULT_TERMINAL_MAX_OUTPUT_BYTES,
            HARD_TERMINAL_MAX_OUTPUT_BYTES,
            "terminal.run",
        )?;
        let timeout_ms = optional_bounded_u64(
            &m,
            "timeout_ms",
            DEFAULT_TERMINAL_TIMEOUT_MS,
            HARD_TERMINAL_TIMEOUT_MS,
            "terminal.run",
        )?;
        let args: Vec<String> = match m.get("args").map(Value::view) {
            Some(ValueView::List(xs)) => {
                let mut args = Vec::with_capacity(xs.len());
                for value in xs {
                    let arg = value.as_str().ok_or_else(|| {
                        DriverError::InvalidInput("terminal.run args must be strings".into())
                    })?;
                    args.push(arg.to_string());
                }
                args
            }
            Some(_) => {
                return Err(DriverError::InvalidInput(
                    "terminal.run args must be a list".into(),
                ));
            }
            None => Vec::new(),
        };
        let output = self
            .runtime
            .run(
                ctx.operation_id.ok_or_else(|| {
                    DriverError::InvalidInput(
                        "terminal.run requires an originating OperationId before spawning".into(),
                    )
                })?,
                cmd,
                args,
                max_output_bytes,
                timeout_ms,
            )
            .await?;

        let mut result = BTreeMap::new();
        result.insert(
            "status".into(),
            Value::integer(output.status.code().unwrap_or(-1) as i64),
        );
        result.insert(
            "stdout".into(),
            Value::string(String::from_utf8_lossy(&output.stdout).into_owned()),
        );
        result.insert(
            "stderr".into(),
            Value::string(String::from_utf8_lossy(&output.stderr).into_owned()),
        );
        result.insert(
            "stdout_truncated".into(),
            Value::boolean(output.stdout_truncated),
        );
        result.insert(
            "stderr_truncated".into(),
            Value::boolean(output.stderr_truncated),
        );
        Ok(DriverOutput::new(Outcome::Done(Value::map(result))))
    }
}

struct TerminalOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct LimitedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

struct TerminalRequest {
    operation_id: OperationId,
    cmd: String,
    args: Vec<String>,
    max_output_bytes: usize,
    timeout_ms: u64,
    deadline: tokio::time::Instant,
}

async fn supervise_terminal(
    request: TerminalRequest,
    mut closed: watch::Receiver<bool>,
    result: &mut oneshot::Sender<Result<TerminalOutput, DriverError>>,
    _slot: &TerminalSlot,
) -> Result<TerminalOutput, DriverError> {
    let TerminalRequest {
        operation_id,
        cmd,
        args,
        max_output_bytes,
        timeout_ms,
        deadline,
    } = request;
    if *closed.borrow() || result.is_closed() {
        return Err(DriverError::Other(
            "terminal call closed before spawn".into(),
        ));
    }
    if tokio::time::Instant::now() >= deadline {
        return Err(DriverError::Other(format!(
            "terminal command exceeded timeout_ms {timeout_ms}"
        )));
    }
    let mut child = tokio::process::Command::new(&cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| DriverError::Other(format!("terminal command {cmd:?} failed: {error}")))?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let diagnostics = kill_and_reap(&mut child).await;
        return Err(DriverError::OutcomeUnknown {
            operation_id: operation_id.to_string(),
            reason: format!("terminal output pipes unavailable{diagnostics}"),
        });
    };
    let mut output = tokio::select! {
        biased;
        _ = closed.wait_for(|value| *value) => Err(DriverError::Other("terminal runtime closed".into())),
        _ = result.closed() => Err(DriverError::Other("terminal call cancelled".into())),
        _ = tokio::time::sleep_until(deadline) => Err(DriverError::Other(format!("terminal command exceeded timeout_ms {timeout_ms}"))),
        output = async {
            let (status, stdout, stderr) = tokio::try_join!(
                child.wait(),
                read_limited_output(stdout, max_output_bytes),
                read_limited_output(stderr, max_output_bytes),
            ).map_err(|error| DriverError::Other(format!("terminal command I/O failed: {error}")))?;
            Ok(TerminalOutput {
                status,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
                stdout_truncated: stdout.truncated,
                stderr_truncated: stderr.truncated,
            })
        } => output,
    };
    if output.is_err() {
        #[cfg(test)]
        {
            let gate = _slot.inner.cleanup_gate.lock().take();
            if let Some((entered, release)) = gate {
                let _entered = entered.send(());
                let _released = release.await;
            }
        }
        let diagnostics = kill_and_reap(&mut child).await;
        if !diagnostics.is_empty()
            && let Err(error) = output
        {
            output = Err(DriverError::Other(format!("{error}{diagnostics}")));
        }
    }
    output.map_err(|error| DriverError::OutcomeUnknown {
        operation_id: operation_id.to_string(),
        reason: error.to_string(),
    })
}

async fn kill_and_reap(child: &mut tokio::process::Child) -> String {
    let mut diagnostics = String::new();
    if let Err(error) = child.start_kill() {
        diagnostics.push_str(&format!("; kill failed: {error}"));
    }
    let mut first_wait_error = true;
    let mut delay = Duration::from_millis(100);
    while let Err(error) = child.wait().await {
        if first_wait_error {
            diagnostics.push_str(&format!("; reap failed before retry: {error}"));
            first_wait_error = false;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
    diagnostics
}

async fn read_limited_output<R>(
    mut reader: R,
    max_output_bytes: usize,
) -> Result<LimitedOutput, std::io::Error>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(max_output_bytes.min(8192));
    let mut buf = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        let remaining = max_output_bytes.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = remaining.min(read);
            bytes.extend_from_slice(&buf[..keep]);
        }
        if read > remaining {
            truncated = true;
        }
    }
    Ok(LimitedOutput { bytes, truncated })
}

fn optional_bounded_usize(
    m: &ValueMap,
    field: &'static str,
    default: usize,
    hard_limit: usize,
    op: &'static str,
) -> Result<usize, DriverError> {
    let Some(value) = m.get(field) else {
        return Ok(default);
    };
    let Some(raw) = value.as_int() else {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        )));
    };
    if raw < 0 {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be nonnegative"
        )));
    }
    let parsed = usize::try_from(raw)
        .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range")))?;
    if parsed > hard_limit {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` exceeds hard limit {hard_limit}"
        )));
    }
    Ok(parsed)
}

fn optional_bounded_u64(
    m: &ValueMap,
    field: &'static str,
    default: u64,
    hard_limit: u64,
    op: &'static str,
) -> Result<u64, DriverError> {
    let Some(value) = m.get(field) else {
        return Ok(default);
    };
    let Some(raw) = value.as_int() else {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        )));
    };
    if raw <= 0 {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be positive"
        )));
    }
    let parsed = u64::try_from(raw)
        .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range")))?;
    if parsed > hard_limit {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` exceeds hard limit {hard_limit}"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_types::{IdentityRef, ProcessId};

    fn test_operation_id() -> OperationId {
        OperationId::new(
            ProcessId::new(1),
            xolotl_types::ExecutionId::FIRST,
            xolotl_types::InvocationId::new(1),
            xolotl_types::NodeId::ROOT,
            0,
        )
    }

    #[tokio::test]
    async fn missing_operation_identity_is_rejected_before_admission() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let driver = TerminalDriver::new(vec!["echo".into()], runtime.clone());
        let result = driver
            .call(
                MethodId::new(0),
                run_input("echo", &[]),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)),
            )
            .await;
        ensure!(
            matches!(result, Err(DriverError::InvalidInput(message)) if message.contains("OperationId"))
        );
        ensure!(*runtime.inner.active.borrow() == 0);
        runtime.shutdown().await;
        Ok(())
    }

    fn run_input(command: &str, args: &[&str]) -> Value {
        let mut m = BTreeMap::new();
        m.insert("command".into(), Value::string(command.into()));
        m.insert(
            "args".into(),
            Value::list(args.iter().map(|a| Value::string((*a).into())).collect()),
        );
        Value::map(m)
    }

    #[tokio::test]
    async fn disallowed_command_rejected() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()], TerminalRuntime::default());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(test_operation_id());
        let out = d
            .call(
                MethodId::new(0),
                run_input("rm", &["-rf", "/"]),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(out.is_err(), "non-allowlisted command must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn allowed_echo_runs_without_shell() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()], TerminalRuntime::default());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(test_operation_id());
        let out = d
            .call(
                MethodId::new(0),
                run_input("echo", &["hello $HOME"]),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run echo command")?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let stdout = m.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                ensure!(
                    stdout.contains("$HOME"),
                    "expected literal argument, got stdout {stdout:?}"
                );
                Ok(())
            }
            other => bail!("expected map result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn output_is_bounded_and_marked_when_truncated() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()], TerminalRuntime::default());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(test_operation_id());
        let mut input = run_input("echo", &["abcdef"])
            .into_map()
            .context("expected map input")?;
        input.insert("max_output_bytes".into(), Value::integer(4))?;
        let out = d
            .call(
                MethodId::new(0),
                Value::from(input),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run bounded echo command")?;
        match out.outcome {
            Outcome::Done(m_value) => {
                let m = m_value.as_map().context("expected map")?;
                let stdout = m.get("stdout").and_then(|v| v.as_str());
                ensure!(stdout == Some("abcd"), "unexpected stdout: {stdout:?}");
                ensure!(
                    m.get("stdout_truncated") == Some(&Value::boolean(true)),
                    "stdout truncation flag missing: {m:?}"
                );
                Ok(())
            }
            other => bail!("expected map result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_bounds_are_rejected() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()], TerminalRuntime::default());
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(test_operation_id());
        for (field, value) in [
            ("max_output_bytes", Value::integer(-1)),
            ("timeout_ms", Value::integer(0)),
            ("timeout_ms", Value::string("1".into())),
        ] {
            let mut input = run_input("echo", &["hello"])
                .into_map()
                .context("expected map input")?;
            input.insert(field.into(), value)?;
            let out = d
                .call(
                    MethodId::new(0),
                    Value::from(input),
                    OutputMode::Unary,
                    &ctx,
                )
                .await;
            ensure!(out.is_err(), "malformed {field} was accepted");
        }
        Ok(())
    }

    #[tokio::test]
    async fn denylisted_command_refused_even_if_allowlisted() -> Result<()> {
        let d = TerminalDriver::new(
            vec!["sudo".into(), "echo".into()],
            TerminalRuntime::default(),
        );
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_operation_id(test_operation_id());
        let out = d
            .call(
                MethodId::new(0),
                run_input("sudo", &["echo", "hi"]),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        match out {
            Err(DriverError::Other(msg)) if msg.contains("denylist") => Ok(()),
            other => bail!("denylisted command must be refused, got {other:?}"),
        }
    }

    #[test]
    fn host_policy_is_the_only_command_gate() -> Result<()> {
        let driver = TerminalDriver::new(
            vec!["rm".into(), "echo".into(), "/usr/bin/sudo".into()],
            TerminalRuntime::default(),
        )
        .with_denylist(vec!["/bin/echo".into()]);
        ensure!(driver.gate("rm").is_ok());
        ensure!(driver.gate("echo").is_err());
        ensure!(driver.gate("/usr/bin/sudo").is_err());
        ensure!(driver.gate("cat").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn retired_approval_input_is_rejected_not_verified() -> Result<()> {
        let driver = TerminalDriver::new(vec!["echo".into()], TerminalRuntime::default());
        for approved in [
            Value::boolean(true),
            Value::boolean(false),
            Value::string("true".into()),
        ] {
            let mut input = run_input("echo", &[]).into_map().context("input map")?;
            input.insert("approved".into(), approved)?;
            let result = driver
                .call(
                    MethodId::new(0),
                    Value::from(input),
                    OutputMode::Unary,
                    &DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
                        .with_operation_id(test_operation_id()),
                )
                .await;
            ensure!(
                matches!(result, Err(DriverError::InvalidInput(message)) if message.contains("no longer accepts"))
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_and_cancellation_plateau_workload() -> Result<()> {
        let runtime = TerminalRuntime::new(NonZeroUsize::MIN);
        for _iteration in 0..64 {
            let output = runtime
                .run(
                    test_operation_id(),
                    "seq".into(),
                    vec!["1".into(), "100000".into()],
                    64 * 1024,
                    5000,
                )
                .await?;
            ensure!(output.stdout.len() == 64 * 1024 && output.stdout_truncated);
            drop(output);
            let call_runtime = runtime.clone();
            let call = tokio::spawn(async move {
                call_runtime
                    .run(test_operation_id(), "yes".into(), vec![], 64 * 1024, 5000)
                    .await
            });
            tokio::time::sleep(Duration::from_millis(10)).await;
            call.abort();
            ensure!(call.await.is_err_and(|error| error.is_cancelled()));
            let mut active = runtime.inner.active.subscribe();
            tokio::time::timeout(Duration::from_secs(5), active.wait_for(|count| *count == 0))
                .await??;
        }
        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn close_rejects_and_shutdown_supports_concurrent_waiters() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let mut slots = Vec::new();
        for _index in 0..16 {
            slots.push(runtime.admit()?);
        }
        ensure!(runtime.admit().is_err(), "default capacity was not finite");
        runtime.close();
        runtime.close();
        ensure!(runtime.admit().is_err());
        let mut interrupted = Box::pin(runtime.shutdown());
        ensure!(
            std::future::poll_fn(|context| std::task::Poll::Ready(
                interrupted.as_mut().poll(context)
            ))
            .await
            .is_pending()
        );
        drop(interrupted);
        drop(slots);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(runtime.shutdown(), runtime.shutdown());
        })
        .await?;
        ensure!(runtime.admit().is_err(), "shutdown reopened admission");
        Ok(())
    }

    #[cfg(unix)]
    struct ProcessFixture {
        directory: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl ProcessFixture {
        fn new() -> Result<Self> {
            Ok(Self {
                directory: tempfile::tempdir()?,
            })
        }

        fn args(&self, parent_waits: bool) -> Vec<String> {
            vec![
                "-c".into(),
                format!(
                    "sleep 30 & printf '%s %s' \"$$\" \"$!\" > \"$1\"; {}",
                    if parent_waits { "wait" } else { "exit 0" },
                ),
                "terminal-test".into(),
                self.directory.path().join("pids").display().to_string(),
            ]
        }

        async fn ready(&self) -> Result<Vec<String>> {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(contents) =
                        std::fs::read_to_string(self.directory.path().join("pids"))
                    {
                        let pids: Vec<String> =
                            contents.split_whitespace().map(str::to_owned).collect();
                        if pids.len() == 2 {
                            return pids;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .context("child did not start")
        }
    }

    #[cfg(unix)]
    impl Drop for ProcessFixture {
        fn drop(&mut self) {
            if let Ok(contents) = std::fs::read_to_string(self.directory.path().join("pids")) {
                let _killed = std::process::Command::new("kill")
                    .arg("-KILL")
                    .args(contents.split_whitespace().skip(1))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_keeps_capacity_until_cleanup_and_reaps_direct_child() -> Result<()> {
        let runtime = TerminalRuntime::new(NonZeroUsize::new(1).context("nonzero")?);
        let fixture = ProcessFixture::new()?;
        let (entered, cleanup_started) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        *runtime.inner.cleanup_gate.lock() = Some((entered, gate));
        let call_runtime = runtime.clone();
        let args = fixture.args(true);
        let call = tokio::spawn(async move {
            call_runtime
                .run(test_operation_id(), "sh".into(), args, 1024, 10_000)
                .await
        });
        let pids = fixture.ready().await?;
        call.abort();
        ensure!(call.await.is_err_and(|error| error.is_cancelled()));
        tokio::time::timeout(Duration::from_secs(5), cleanup_started).await??;
        ensure!(
            runtime.admit().is_err(),
            "caller cancellation released cleanup capacity"
        );
        let rejected = runtime
            .run(test_operation_id(), "echo".into(), vec![], 1024, 100)
            .await;
        ensure!(
            matches!(rejected, Err(DriverError::Other(message)) if message.contains("capacity"))
        );
        let mut drain = Box::pin(runtime.shutdown());
        ensure!(
            std::future::poll_fn(|context| std::task::Poll::Ready(drain.as_mut().poll(context)))
                .await
                .is_pending()
        );
        drop(drain);
        release
            .send(())
            .map_err(|()| anyhow::anyhow!("cleanup supervisor lost"))?;
        tokio::time::timeout(Duration::from_secs(5), runtime.shutdown()).await?;
        let alive = std::process::Command::new("kill")
            .args(["-0", &pids[0]])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        ensure!(!alive, "direct child not reaped");
        ensure!(*runtime.inner.active.borrow() == 0);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_includes_pipes_held_by_descendants_after_child_exit() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let fixture = ProcessFixture::new()?;
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            runtime.run(
                test_operation_id(),
                "sh".into(),
                fixture.args(false),
                1024,
                100,
            ),
        )
        .await?;
        ensure!(
            matches!(output, Err(DriverError::OutcomeUnknown { operation_id, reason })
                if operation_id == test_operation_id().to_string() && reason.contains("timeout_ms"))
        );
        ensure!(*runtime.inner.active.borrow() == 0);
        runtime.shutdown().await;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_cancels_pipes_held_by_descendants() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let fixture = ProcessFixture::new()?;
        let call_runtime = runtime.clone();
        let args = fixture.args(false);
        let call = tokio::spawn(async move {
            call_runtime
                .run(test_operation_id(), "sh".into(), args, 1024, 10_000)
                .await
        });
        fixture.ready().await?;
        tokio::time::timeout(Duration::from_secs(5), runtime.shutdown()).await?;
        ensure!(
            matches!(call.await?, Err(DriverError::OutcomeUnknown { operation_id, reason })
            if operation_id == test_operation_id().to_string() && reason.contains("closed"))
        );
        ensure!(*runtime.inner.active.borrow() == 0);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn caller_cancellation_finishes_without_descendant_pipe_eof() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let fixture = ProcessFixture::new()?;
        let call_runtime = runtime.clone();
        let args = fixture.args(false);
        let call = tokio::spawn(async move {
            call_runtime
                .run(test_operation_id(), "sh".into(), args, 1024, 10_000)
                .await
        });
        let pids = fixture.ready().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let alive = std::process::Command::new("kill")
                    .args(["-0", &pids[0]])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?;
                if !alive.success() {
                    return Ok::<(), std::io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        ensure!(
            !call.is_finished(),
            "call finished before inherited pipes closed"
        );
        call.abort();
        ensure!(call.await.is_err_and(|error| error.is_cancelled()));
        let mut active = runtime.inner.active.subscribe();
        tokio::time::timeout(Duration::from_secs(5), active.wait_for(|count| *count == 0))
            .await??;
        ensure!(
            runtime
                .run(test_operation_id(), "echo".into(), vec![], 1024, 1000)
                .await
                .is_ok(),
            "cleanup did not return capacity"
        );
        runtime.shutdown().await;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn close_before_supervisor_starts_prevents_spawn() -> Result<()> {
        let runtime = TerminalRuntime::default();
        let fixture = ProcessFixture::new()?;
        let mut call = Box::pin(runtime.run(
            test_operation_id(),
            "sh".into(),
            fixture.args(true),
            1024,
            1000,
        ));
        ensure!(
            std::future::poll_fn(|context| std::task::Poll::Ready(call.as_mut().poll(context)))
                .await
                .is_pending()
        );
        runtime.close();
        ensure!(
            matches!(call.await, Err(DriverError::Other(message)) if message.contains("before spawn"))
        );
        runtime.shutdown().await;
        ensure!(
            !fixture.directory.path().join("pids").exists(),
            "closed runtime spawned a child"
        );
        Ok(())
    }
}
