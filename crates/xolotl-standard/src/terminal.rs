//! Terminal provider: `effect://terminal/run`.
//!
//! Safety: **never** goes through a shell — input is `command +
//! Vec<String>` args, executed directly. These checks gate every run:
//!
//! - the kernel must have granted `effect://terminal/run` before the driver is
//!   reached;
//! - the command must be on the allowlist and off the denylist;
//! - known destructive commands require `approved: true`.
//!
//! `run` is `Effectful` → `NonIdempotentEffect`. Process finalize sends SIGTERM
//! then SIGKILL; this one-shot run records the command result.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Child;
use xolotl_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, Purity, Value};

const DEFAULT_TERMINAL_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const HARD_TERMINAL_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TERMINAL_TIMEOUT_MS: u64 = 30_000;
const HARD_TERMINAL_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Method names for `effect://terminal/run`; the public method is `invoke`
/// after standard installation.
pub(crate) const TERMINAL_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "run",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Commands always refused regardless of the allowlist.
/// These have no safe argv form through this one-shot, shell-free runner.
pub(crate) const DEFAULT_DENYLIST: &[&str] =
    &["sudo", "su", "doas", "chroot", "nc", "ncat", "telnet"];

/// Known-destructive commands that require explicit approval.
pub(crate) const DEFAULT_HIGH_RISK: &[&str] = &[
    "rm", "rmdir", "dd", "mkfs", "fdisk", "shutdown", "reboot", "halt", "poweroff", "kill",
    "killall", "chmod", "chown", "mount", "umount",
];

/// Drives `effect://terminal/run`. A command must be on the allowlist and off the
/// denylist; high-risk commands additionally require `approved: true`. Args are
/// passed verbatim (no shell, no glob/var expansion).
pub(crate) struct TerminalDriver {
    allowlist: Vec<String>,
    denylist: Vec<String>,
    high_risk: Vec<String>,
}

impl TerminalDriver {
    /// Construct with an allowlist and the built-in denylist / high-risk sets.
    pub(crate) fn new(allowlist: Vec<String>) -> Self {
        Self {
            allowlist,
            denylist: DEFAULT_DENYLIST.iter().map(|s| s.to_string()).collect(),
            high_risk: DEFAULT_HIGH_RISK.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Add commands to the built-in denylist.
    pub(crate) fn with_denylist(mut self, denylist: Vec<String>) -> Self {
        extend_unique(&mut self.denylist, denylist);
        self
    }

    /// Add commands to the built-in high-risk set.
    pub(crate) fn with_high_risk(mut self, high_risk: Vec<String>) -> Self {
        extend_unique(&mut self.high_risk, high_risk);
        self
    }

    fn allowed(&self, cmd: &str) -> bool {
        self.allowlist.iter().any(|c| c == cmd)
    }

    fn denied(&self, cmd: &str) -> bool {
        self.denylist.iter().any(|c| command_matches(cmd, c))
    }

    fn high_risk(&self, cmd: &str) -> bool {
        self.high_risk.iter().any(|c| command_matches(cmd, c))
    }

    /// Check whether the command may proceed to spawn.
    fn gate(&self, cmd: &str, approved: bool) -> Result<(), DriverError> {
        if self.denied(cmd) {
            return Err(DriverError::Other(format!("command is denylisted: {cmd}")));
        }
        // Allowlist check: the command must be explicitly allowed.
        if !self.allowed(cmd) {
            return Err(DriverError::Other(format!(
                "command not on allowlist: {cmd}"
            )));
        }
        // Approval check: high-risk commands need explicit approval.
        if self.high_risk(cmd) && !approved {
            return Err(DriverError::Other(format!(
                "command `{cmd}` is high-risk and requires approval (set `approved: true`)"
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
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let m = crate::input::map(input, "terminal.run")?;
        let cmd = m
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("terminal.run requires `command`".into()))?
            .to_string();
        let approved = optional_bool(&m, "approved", "terminal.run")?;
        self.gate(&cmd, approved)?;
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
        let args: Vec<String> = match m.get("args") {
            Some(Value::List(xs)) => {
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
        let output = run_terminal_command(&cmd, &args, max_output_bytes, timeout_ms).await?;

        let mut result = BTreeMap::new();
        result.insert(
            "status".into(),
            Value::Int(output.status.code().unwrap_or(-1) as i64),
        );
        result.insert(
            "stdout".into(),
            Value::Str(String::from_utf8_lossy(&output.stdout).into_owned()),
        );
        result.insert(
            "stderr".into(),
            Value::Str(String::from_utf8_lossy(&output.stderr).into_owned()),
        );
        result.insert(
            "stdout_truncated".into(),
            Value::Bool(output.stdout_truncated),
        );
        result.insert(
            "stderr_truncated".into(),
            Value::Bool(output.stderr_truncated),
        );
        Ok(Outcome::Done(Value::Map(result)))
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

async fn run_terminal_command(
    cmd: &str,
    args: &[String],
    max_output_bytes: usize,
    timeout_ms: u64,
) -> Result<TerminalOutput, DriverError> {
    let mut child = tokio::process::Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DriverError::Other(format!("terminal command {cmd:?} failed: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| DriverError::Other("terminal stdout pipe was not available".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| DriverError::Other("terminal stderr pipe was not available".into()))?;
    let stdout_task = tokio::spawn(read_limited_output(stdout, max_output_bytes));
    let stderr_task = tokio::spawn(read_limited_output(stderr, max_output_bytes));
    let status = match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait()).await {
        Ok(status) => {
            status.map_err(|e| DriverError::Other(format!("terminal command wait failed: {e}")))?
        }
        Err(_elapsed) => {
            return terminal_timeout_error(child, stdout_task, stderr_task, timeout_ms).await;
        }
    };
    let stdout = join_limited_output(stdout_task, "stdout").await?;
    let stderr = join_limited_output(stderr_task, "stderr").await?;
    Ok(TerminalOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
    })
}

async fn terminal_timeout_error(
    mut child: Child,
    stdout_task: tokio::task::JoinHandle<Result<LimitedOutput, std::io::Error>>,
    stderr_task: tokio::task::JoinHandle<Result<LimitedOutput, std::io::Error>>,
    timeout_ms: u64,
) -> Result<TerminalOutput, DriverError> {
    let mut details = vec![format!("terminal command exceeded timeout_ms {timeout_ms}")];
    if let Err(error) = child.kill().await {
        details.push(format!("kill failed: {error}"));
    }
    if let Err(error) = child.wait().await {
        details.push(format!("wait after kill failed: {error}"));
    }
    if let Err(error) = join_limited_output(stdout_task, "stdout").await {
        details.push(error.to_string());
    }
    if let Err(error) = join_limited_output(stderr_task, "stderr").await {
        details.push(error.to_string());
    }
    Err(DriverError::Other(details.join("; ")))
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

async fn join_limited_output(
    task: tokio::task::JoinHandle<Result<LimitedOutput, std::io::Error>>,
    label: &'static str,
) -> Result<LimitedOutput, DriverError> {
    match task.await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(DriverError::Other(format!(
            "terminal {label} read failed: {error}"
        ))),
        Err(error) => Err(DriverError::Other(format!(
            "terminal {label} reader task failed: {error}"
        ))),
    }
}

fn optional_bool(
    m: &BTreeMap<String, Value>,
    field: &'static str,
    op: &'static str,
) -> Result<bool, DriverError> {
    match m.get(field) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be a boolean"
        ))),
    }
}

fn optional_bounded_usize(
    m: &BTreeMap<String, Value>,
    field: &'static str,
    default: usize,
    hard_limit: usize,
    op: &'static str,
) -> Result<usize, DriverError> {
    let Some(value) = m.get(field) else {
        return Ok(default);
    };
    let Value::Int(raw) = value else {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        )));
    };
    if *raw < 0 {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be nonnegative"
        )));
    }
    let parsed = usize::try_from(*raw)
        .map_err(|_error| DriverError::InvalidInput(format!("{op} `{field}` is out of range")))?;
    if parsed > hard_limit {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` exceeds hard limit {hard_limit}"
        )));
    }
    Ok(parsed)
}

fn optional_bounded_u64(
    m: &BTreeMap<String, Value>,
    field: &'static str,
    default: u64,
    hard_limit: u64,
    op: &'static str,
) -> Result<u64, DriverError> {
    let Some(value) = m.get(field) else {
        return Ok(default);
    };
    let Value::Int(raw) = value else {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be an integer"
        )));
    };
    if *raw <= 0 {
        return Err(DriverError::InvalidInput(format!(
            "{op} `{field}` must be positive"
        )));
    }
    let parsed = u64::try_from(*raw)
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

    fn run_input(command: &str, args: &[&str]) -> Value {
        let mut m = BTreeMap::new();
        m.insert("command".into(), Value::Str(command.into()));
        m.insert(
            "args".into(),
            Value::List(args.iter().map(|a| Value::Str((*a).into())).collect()),
        );
        Value::Map(m)
    }

    #[tokio::test]
    async fn disallowed_command_rejected() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
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
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                run_input("echo", &["hello $HOME"]),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .context("run echo command")?;
        match out {
            Outcome::Done(Value::Map(m)) => {
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
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut input = match run_input("echo", &["abcdef"]) {
            Value::Map(map) => map,
            other => bail!("expected map input, got {other:?}"),
        };
        input.insert("max_output_bytes".into(), Value::Int(4));
        let out = d
            .call(MethodId::new(0), Value::Map(input), OutputMode::Unary, &ctx)
            .await
            .context("run bounded echo command")?;
        match out {
            Outcome::Done(Value::Map(m)) => {
                let stdout = m.get("stdout").and_then(|v| v.as_str());
                ensure!(stdout == Some("abcd"), "unexpected stdout: {stdout:?}");
                ensure!(
                    m.get("stdout_truncated") == Some(&Value::Bool(true)),
                    "stdout truncation flag missing: {m:?}"
                );
                Ok(())
            }
            other => bail!("expected map result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_bounds_are_rejected() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        for (field, value) in [
            ("max_output_bytes", Value::Int(-1)),
            ("timeout_ms", Value::Int(0)),
            ("timeout_ms", Value::Str("1".into())),
        ] {
            let mut input = match run_input("echo", &["hello"]) {
                Value::Map(map) => map,
                other => bail!("expected map input, got {other:?}"),
            };
            input.insert(field.into(), value);
            let out = d
                .call(MethodId::new(0), Value::Map(input), OutputMode::Unary, &ctx)
                .await;
            ensure!(out.is_err(), "malformed {field} was accepted");
        }
        Ok(())
    }

    #[tokio::test]
    async fn denylisted_command_refused_even_if_allowlisted() -> Result<()> {
        let d = TerminalDriver::new(vec!["sudo".into(), "echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
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

    #[tokio::test]
    async fn high_risk_command_requires_approval() -> Result<()> {
        let d = TerminalDriver::new(vec!["rm".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let out = d
            .call(
                MethodId::new(0),
                run_input("rm", &["-rf", "/tmp/x"]),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        match out {
            Err(DriverError::Other(msg)) if msg.contains("approval") => Ok(()),
            other => bail!("high-risk command must require approval, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_approval_flag_is_rejected() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        let mut input = BTreeMap::new();
        input.insert("command".into(), Value::Str("echo".into()));
        input.insert("approved".into(), Value::Str("true".into()));
        let out = d
            .call(MethodId::new(0), Value::Map(input), OutputMode::Unary, &ctx)
            .await;
        ensure!(
            matches!(out, Err(DriverError::InvalidInput(ref message)) if message.contains("approved")),
            "terminal accepted malformed approved flag: {out:?}"
        );
        Ok(())
    }

    #[test]
    fn gate_layers_compose() -> Result<()> {
        let d = TerminalDriver::new(vec!["echo".into(), "rm".into(), "sudo".into()]);
        ensure!(d.gate("echo", false).is_ok(), "allowlisted command failed");
        ensure!(d.gate("cat", false).is_err(), "unlisted command passed");
        ensure!(d.gate("sudo", true).is_err(), "denylisted command passed");
        ensure!(
            d.gate("rm", false).is_err(),
            "high-risk command passed without approval"
        );
        ensure!(
            d.gate("rm", true).is_ok(),
            "approved high-risk command failed"
        );
        Ok(())
    }

    #[test]
    fn custom_denylist_and_high_risk_extend_defaults() -> Result<()> {
        let d = TerminalDriver::new(vec!["git".into(), "echo".into()])
            .with_denylist(vec!["git".into()])
            .with_high_risk(vec!["echo".into()]);
        ensure!(d.gate("git", true).is_err(), "custom denylist refuses git");
        ensure!(
            d.gate("echo", false).is_err(),
            "custom high-risk gates echo"
        );
        ensure!(
            d.gate("echo", true).is_ok(),
            "approval clears custom high-risk"
        );
        Ok(())
    }

    #[test]
    fn basename_is_checked_for_denylist_and_high_risk() -> Result<()> {
        let d = TerminalDriver::new(vec!["/usr/bin/sudo".into(), "/bin/rm".into()]);
        ensure!(
            d.gate("/usr/bin/sudo", true).is_err(),
            "denylist must match command basename"
        );
        ensure!(
            d.gate("/bin/rm", false).is_err(),
            "high-risk list must match command basename"
        );
        ensure!(
            d.gate("/bin/rm", true).is_ok(),
            "approved high-risk basename should pass when allowlisted"
        );
        Ok(())
    }

    #[test]
    fn listed_absolute_paths_match_command_basename_for_safety_sets() -> Result<()> {
        let d = TerminalDriver::new(vec!["sudo".into(), "rm".into()])
            .with_denylist(vec!["/usr/bin/sudo".into()])
            .with_high_risk(vec!["/bin/rm".into()]);
        ensure!(
            d.gate("sudo", true).is_err(),
            "absolute denylist entry must match command basename"
        );
        ensure!(
            d.gate("rm", false).is_err(),
            "absolute high-risk entry must match command basename"
        );
        ensure!(
            d.gate("rm", true).is_ok(),
            "approval clears absolute high-risk match"
        );
        Ok(())
    }
}
