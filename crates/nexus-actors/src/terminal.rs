//! Terminal provider (§17.3): `effect://terminal/run`.
//!
//! Safety (§17.3): **never** goes through a shell — input is `command +
//! Vec<String>` args, executed directly. Three layers of protection gate every
//! run ("三层防护:策略能力 + 命令 allowlist/denylist + 高危命令 Approval"):
//!
//! 1. **Policy capability** — enforced upstream by the kernel before the driver
//!    is even reached (the Operation must hold the `effect://terminal/run`
//!    grant); not re-checked here.
//! 2. **allowlist / denylist** — a command must be on the allowlist *and* off
//!    the denylist. The denylist always wins, so a footgun cannot be opened up
//!    by a permissive allowlist.
//! 3. **high-risk Approval** — a known-destructive command (`rm`, `dd`, `mkfs`,
//!    `shutdown`, …) is refused unless the input carries `approved: true`. The
//!    real approval flow lives elsewhere (`effect://approval/ask`); this driver
//!    only gates on the resolved flag.
//!
//! `run` is `Effectful` → `NonIdempotentEffect`. Process finalize sends SIGTERM
//! then SIGKILL (not modeled in the spine's one-shot run).

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;

/// Method names for `effect://terminal/run`; the public method is `invoke`
/// after standard installation.
pub const TERMINAL_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "run",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Commands always refused regardless of the allowlist (layer 2 denylist).
/// These have no safe argv form through this one-shot, shell-free runner.
pub const DEFAULT_DENYLIST: &[&str] = &["sudo", "su", "doas", "chroot", "nc", "ncat", "telnet"];

/// Known-destructive commands that require explicit Approval (layer 3). They may
/// still run, but only when the Operation input resolves `approved: true`.
pub const DEFAULT_HIGH_RISK: &[&str] = &[
    "rm", "rmdir", "dd", "mkfs", "fdisk", "shutdown", "reboot", "halt", "poweroff", "kill",
    "killall", "chmod", "chown", "mount", "umount",
];

/// Drives `effect://terminal/run`. A command must be on the allowlist and off the
/// denylist; high-risk commands additionally require `approved: true`. Args are
/// passed verbatim (no shell, no glob/var expansion).
pub struct TerminalDriver {
    allowlist: Vec<String>,
    denylist: Vec<String>,
    high_risk: Vec<String>,
}

impl TerminalDriver {
    /// Construct with an allowlist and the built-in denylist / high-risk sets.
    pub fn new(allowlist: Vec<String>) -> Self {
        Self {
            allowlist,
            denylist: DEFAULT_DENYLIST.iter().map(|s| s.to_string()).collect(),
            high_risk: DEFAULT_HIGH_RISK.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Override the denylist (layer 2). Builder; chains with [`Self::new`].
    pub fn with_denylist(mut self, denylist: Vec<String>) -> Self {
        self.denylist = denylist;
        self
    }

    /// Override the high-risk set (layer 3). Builder; chains with [`Self::new`].
    pub fn with_high_risk(mut self, high_risk: Vec<String>) -> Self {
        self.high_risk = high_risk;
        self
    }

    fn allowed(&self, cmd: &str) -> bool {
        self.allowlist.iter().any(|c| c == cmd)
    }

    fn denied(&self, cmd: &str) -> bool {
        self.denylist.iter().any(|c| c == cmd)
    }

    fn high_risk(&self, cmd: &str) -> bool {
        self.high_risk.iter().any(|c| c == cmd)
    }

    /// Run the three-layer gate (denylist → allowlist → high-risk Approval).
    /// Returns `Ok(())` if the command may proceed to spawn. Pulled out of
    /// `call` so it is unit-testable without an actual subprocess.
    fn gate(&self, cmd: &str, approved: bool) -> Result<(), DriverError> {
        // Layer 2a: denylist always wins, even over an allowlist entry.
        if self.denied(cmd) {
            return Err(DriverError::Other(format!("command is denylisted: {cmd}")));
        }
        // Layer 2b: must be explicitly allowlisted.
        if !self.allowed(cmd) {
            return Err(DriverError::Other(format!(
                "command not on allowlist: {cmd}"
            )));
        }
        // Layer 3: high-risk commands need Approval.
        if self.high_risk(cmd) && !approved {
            return Err(DriverError::Other(format!(
                "command `{cmd}` is high-risk and requires approval (set `approved: true`)"
            )));
        }
        Ok(())
    }
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
        let m = input.as_map().cloned().unwrap_or_default();
        let cmd = m
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DriverError::Other("terminal.run requires `command`".into()))?
            .to_string();
        let approved = m.get("approved").and_then(|v| v.as_bool()).unwrap_or(false);
        // Three-layer gate (denylist → allowlist → high-risk Approval) runs
        // before any spawn.
        self.gate(&cmd, approved)?;
        let args: Vec<String> = match m.get("args") {
            Some(Value::List(xs)) => xs
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => vec![],
        };
        // Direct exec — NO shell. tokio::process::Command does not interpret
        // metacharacters; args are passed as a literal argv.
        let output = tokio::process::Command::new(&cmd)
            .args(&args)
            .output()
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;

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
        Ok(Outcome::Done(Value::Map(result)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{IdentityRef, ProcessId};

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
    async fn disallowed_command_rejected() {
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
        assert!(out.is_err(), "non-allowlisted command must be rejected");
    }

    #[tokio::test]
    async fn allowed_echo_runs_without_shell() {
        let d = TerminalDriver::new(vec!["echo".into()]);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
        // The arg with a metacharacter is passed literally (no shell expansion).
        let out = d
            .call(
                MethodId::new(0),
                run_input("echo", &["hello $HOME"]),
                OutputMode::Unary,
                &ctx,
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(m)) => {
                let stdout = m.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                assert!(stdout.contains("$HOME"), "no shell expansion: {stdout}");
            }
            _ => panic!("expected map result"),
        }
    }

    #[tokio::test]
    async fn denylisted_command_refused_even_if_allowlisted() {
        // `sudo` is on the allowlist but also on the built-in denylist → denied.
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
            Err(DriverError::Other(msg)) => assert!(msg.contains("denylist"), "got: {msg}"),
            other => panic!("denylisted command must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn high_risk_command_requires_approval() {
        // `rm` is allowlisted and not denylisted, but high-risk without approval.
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
            Err(DriverError::Other(msg)) => assert!(msg.contains("approval"), "got: {msg}"),
            other => panic!("high-risk command must require approval, got {other:?}"),
        }
    }

    #[test]
    fn gate_layers_compose() {
        // Unit-test the gate directly so the high-risk *approved* path is covered
        // without spawning a subprocess (fork/exec is blocked under the sandbox).
        let d = TerminalDriver::new(vec!["echo".into(), "rm".into(), "sudo".into()]);
        // Plain allowlisted command: passes.
        assert!(d.gate("echo", false).is_ok());
        // Not allowlisted: refused.
        assert!(d.gate("cat", false).is_err());
        // Denylisted (even though allowlisted): refused regardless of approval.
        assert!(d.gate("sudo", true).is_err());
        // High-risk without approval: refused; with approval: passes.
        assert!(d.gate("rm", false).is_err());
        assert!(d.gate("rm", true).is_ok());
    }

    #[test]
    fn custom_denylist_and_high_risk_override() {
        let d = TerminalDriver::new(vec!["git".into(), "echo".into()])
            .with_denylist(vec!["git".into()])
            .with_high_risk(vec!["echo".into()]);
        assert!(d.gate("git", true).is_err(), "custom denylist refuses git");
        assert!(
            d.gate("echo", false).is_err(),
            "custom high-risk gates echo"
        );
        assert!(
            d.gate("echo", true).is_ok(),
            "approval clears custom high-risk"
        );
    }
}
