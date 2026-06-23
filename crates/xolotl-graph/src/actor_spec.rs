//! Actor declarations and capability linting.
//!
//! An [`ActorSpec`] names a long-lived [`DoNode`] body and declares the
//! capability ceiling, budget, and finalizers attached to that body.
//! [`lint`] compares operations found in the body with the declared capability
//! literals.

use crate::r#do::{DoNode, bind_process_self_capability_literal};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use xolotl_types::{BudgetSpec, Capability, PathError, Value};

/// Declaration for a named long-lived `Do<()>` body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorSpec {
    /// Stable actor name.
    #[serde(default)]
    pub name: String,
    /// Durable program body run by the actor process.
    #[serde(default = "default_body")]
    pub body: DoNode,
    /// Capability literals declared for the actor body.
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    /// Budget and inflight limits.
    #[serde(default)]
    pub budget: BudgetSpec,
    /// Finalizers run when the actor process is finalized.
    #[serde(default)]
    pub finalizers: Vec<DoNode>,
}

impl ActorSpec {
    /// A spec declaring only a name and a set of capability literals.
    pub fn with_capabilities<I, S>(name: impl Into<String>, capabilities: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            body: default_body(),
            declared_capabilities: capabilities.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Whether `(verb, target)` is covered by any declared capability literal.
    pub fn declares_capability(
        &self,
        verb: &str,
        target: &str,
    ) -> Result<bool, CapabilityQueryError> {
        let path = xolotl_types::Path::parse(target).map_err(|source| {
            CapabilityQueryError::TargetPath {
                literal: target.to_string(),
                source,
            }
        })?;
        for literal in &self.declared_capabilities {
            let cap =
                Capability::parse(literal).map_err(|source| CapabilityQueryError::Declaration {
                    literal: literal.clone(),
                    source,
                })?;
            if cap.covers(verb, &path) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Bind declaration-time process-local references to a concrete Process.
    pub fn bind_process_local_refs(
        &self,
        process: xolotl_types::ProcessId,
    ) -> Result<Self, ActorBindError> {
        let body = self.body.bind_process_local_refs(process)?;
        let finalizers = self
            .finalizers
            .iter()
            .map(|finalizer| finalizer.bind_process_local_refs(process))
            .collect::<Result<Vec<_>, _>>()?;
        let declared_capabilities = self
            .declared_capabilities
            .iter()
            .map(|literal| {
                bind_process_self_capability_literal(literal, process).map_err(|source| {
                    ActorBindError::Capability {
                        literal: literal.clone(),
                        source,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name: self.name.clone(),
            body,
            declared_capabilities,
            budget: self.budget.clone(),
            finalizers,
        })
    }
}

impl Default for ActorSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            body: default_body(),
            declared_capabilities: Vec::new(),
            budget: BudgetSpec::default(),
            finalizers: Vec::new(),
        }
    }
}

fn default_body() -> DoNode {
    DoNode::pure(Value::Null)
}

/// Error returned by capability coverage queries on an [`ActorSpec`].
#[derive(Debug, thiserror::Error)]
pub enum CapabilityQueryError {
    /// The requested target path is malformed.
    #[error("target path {literal:?} is malformed: {source}")]
    TargetPath {
        /// Target path literal supplied by the caller.
        literal: String,
        /// Path parser error.
        #[source]
        source: PathError,
    },
    /// One declared capability literal is malformed.
    #[error("declared capability {literal:?} is malformed: {source}")]
    Declaration {
        /// Capability literal from the actor spec.
        literal: String,
        /// Capability parser error.
        #[source]
        source: xolotl_types::CapError,
    },
}

/// Error returned while binding process-local Actor references.
#[derive(Debug, thiserror::Error)]
pub enum ActorBindError {
    /// A path containing a process-local placeholder could not be rebound.
    #[error("process-local path binding failed: {0}")]
    Path(#[from] PathError),
    /// A declared capability could not be rebound.
    #[error("declared capability {literal:?} binding failed: {source}")]
    Capability {
        /// Capability literal from the actor spec.
        literal: String,
        /// Capability parser error.
        #[source]
        source: xolotl_types::CapError,
    },
}

/// The severity of a [`LintFinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    /// Security-relevant: the program would exceed the declared ceiling at
    /// runtime.
    Error,
    /// Advisory only.
    Warning,
}

/// One issue found by [`lint`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LintFinding {
    /// Severity assigned to this finding.
    pub severity: LintSeverity,
    /// The operation target the finding is about.
    pub target: String,
    /// The capability verb required for that operation.
    pub verb: String,
    /// The method invoked on that target (context for the operator).
    pub method: String,
    /// Human-readable explanation.
    pub message: String,
}

/// Lint a program's AST against its [`ActorSpec`].
///
/// Flags every capability the program **uses but does not declare**. These are
/// security-relevant because `declared_capabilities` forms the runtime ceiling:
/// an undeclared capability is outside the attenuated task-level Handle set and
/// would be denied. A fully-declared program yields no findings.
///
/// Each distinct undeclared `(target, method)` produces one finding. Declared
/// capabilities that the program never uses are *not* flagged here —
/// over-declaring only widens the ceiling, a separate (advisory) concern.
pub fn lint(spec: &ActorSpec, program: &DoNode) -> Vec<LintFinding> {
    let (declared, mut findings) = parse_declared_capabilities(&spec.declared_capabilities);
    lint_program(program, &declared, &mut findings, None);
    findings
}

/// Lint an actor's declared body and finalizers against its capability ceiling.
pub fn lint_actor(spec: &ActorSpec) -> Vec<LintFinding> {
    let (declared, mut findings) = parse_declared_capabilities(&spec.declared_capabilities);
    lint_program(&spec.body, &declared, &mut findings, None);
    for (index, finalizer) in spec.finalizers.iter().enumerate() {
        lint_program(finalizer, &declared, &mut findings, Some(index));
    }
    findings
}

fn parse_declared_capabilities(literals: &[String]) -> (Vec<Capability>, Vec<LintFinding>) {
    let mut findings = Vec::new();
    let mut declared = Vec::new();
    for literal in literals {
        match Capability::parse(literal) {
            Ok(capability) => declared.push(capability),
            Err(error) => findings.push(LintFinding {
                severity: LintSeverity::Error,
                target: literal.clone(),
                verb: String::new(),
                method: "declared_capabilities".into(),
                message: format!("declared capability `{literal}` is malformed: {error}"),
            }),
        }
    }
    (declared, findings)
}

fn lint_program(
    program: &DoNode,
    declared: &[Capability],
    findings: &mut Vec<LintFinding>,
    finalizer_index: Option<usize>,
) {
    let mut seen = HashSet::new();
    for op in program.ops() {
        let target_path = op.target.path();
        let target = target_path.to_string();
        let verb = operation_capability_verb(&op.method);
        if declared.iter().any(|cap| cap.covers(verb, target_path)) {
            continue;
        }
        let key = (target.clone(), op.method.clone());
        if !seen.insert(key) {
            continue;
        }
        let base_message = format!(
            "capability `{verb}://{}` for method `{}` is used but not declared in \
             ActorSpec.declared_capabilities; it exceeds the task-level ceiling",
            capability_target(&target),
            op.method
        );
        let message = match finalizer_index {
            Some(index) => format!("finalizer[{index}]: {base_message}"),
            None => base_message,
        };
        findings.push(LintFinding {
            severity: LintSeverity::Error,
            target: target.clone(),
            verb: verb.into(),
            method: op.method.clone(),
            message,
        });
    }
}

/// Whether a declared capability literal covers the required `(verb, target)`.
pub fn capability_covers(literal: &str, verb: &str, target: &str) -> bool {
    let Ok(cap) = Capability::parse(literal) else {
        return false;
    };
    let Ok(path) = xolotl_types::Path::parse(target) else {
        return false;
    };
    cap.covers(verb, &path)
}

/// Capability verb required by an operation method name.
pub fn operation_capability_verb(method: &str) -> &'static str {
    match method {
        "read" | "list" => "read",
        "write" | "append" | "delete" => "write",
        "subscribe" => "subscribe",
        _ => "perform",
    }
}

fn capability_target(target: &str) -> String {
    target.replacen("://", "/", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{OperationTemplate, StepRef, WaitSpec};
    use anyhow::{Context, anyhow, bail, ensure};
    use xolotl_types::{OutputMode, Path, ProcessId, ResourceName, Value};

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    fn op(path: &str) -> anyhow::Result<OperationTemplate> {
        Ok(OperationTemplate {
            target: ResourceName::new(
                Path::parse(path)
                    .map_err(|error| anyhow!("path parse failed for {path}: {error}"))?,
            ),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        })
    }

    #[test]
    fn undeclared_capability_is_flagged() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("notifier", ["perform://effect/events/emit"]);
        let program = DoNode::r#let(
            "e",
            DoNode::op(op("effect://events/emit")?),
            DoNode::op(op("effect://fetch/get")?),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(
            finding.target == "effect://fetch/get",
            "unexpected target: {}",
            finding.target
        );
        ensure!(
            finding.verb == "perform",
            "unexpected verb: {}",
            finding.verb
        );
        ensure!(
            finding.severity == LintSeverity::Error,
            "unexpected severity: {:?}",
            finding.severity
        );
        Ok(())
    }

    #[test]
    fn fully_declared_program_is_clean() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities(
            "housekeeper",
            ["perform://effect/fs/read", "perform://effect/events/emit"],
        );
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://fs/read")?)),
            Box::new(DoNode::op(op("effect://events/emit")?)),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn capability_prefix_covers_finer_target() -> anyhow::Result<()> {
        ensure!(
            capability_covers("perform://effect/fs/**", "perform", "effect://fs/read"),
            "wildcard capability did not cover finer target"
        );
        ensure!(
            capability_covers("perform://effect/fs/read", "perform", "effect://fs/read"),
            "exact capability did not cover target"
        );
        ensure!(
            !capability_covers("perform://effect/fs/read", "perform", "effect://fs"),
            "finer target covered coarser target"
        );
        ensure!(
            !capability_covers("perform://effect/fs/**", "perform", "effect://fetch/get"),
            "capability covered different namespace"
        );
        ensure!(
            !capability_covers("effect://fs", "perform", "effect://fs/read"),
            "resource path was treated as capability literal"
        );
        Ok(())
    }

    #[test]
    fn duplicate_undeclared_uses_collapse_to_one_finding() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("a", ["perform://effect/memory/**"]);
        let program = DoNode::Both(
            Box::new(DoNode::op(op("effect://x/post")?)),
            Box::new(DoNode::op(op("effect://x/post")?)),
        );
        let findings = lint(&spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn malformed_declared_capability_is_flagged() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("a", ["effect://x/post"]);
        let findings = lint(&spec, &DoNode::pure(Value::Null));

        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(
            finding.target == "effect://x/post",
            "unexpected target: {}",
            finding.target
        );
        ensure!(
            finding.method == "declared_capabilities",
            "unexpected method: {}",
            finding.method
        );
        ensure!(
            finding.severity == LintSeverity::Error,
            "unexpected severity: {:?}",
            finding.severity
        );
        ensure!(
            matches!(
                spec.declares_capability("perform", "effect://x/post"),
                Err(CapabilityQueryError::Declaration { .. })
            ),
            "malformed declaration should not grant capability"
        );
        Ok(())
    }

    #[test]
    fn state_append_requires_write_capability() -> anyhow::Result<()> {
        let mut append = op("state://events/topic")?;
        append.method = "append".into();
        let program = DoNode::op(append);

        let read_spec = ActorSpec::with_capabilities("reader", ["read://state/events/**"]);
        let findings = lint(&read_spec, &program);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(finding.verb == "write", "unexpected verb: {}", finding.verb);
        ensure!(
            finding
                .message
                .contains("capability `write://state/events/topic`"),
            "unexpected message: {}",
            finding.message
        );

        let write_spec = ActorSpec::with_capabilities("writer", ["write://state/events/**"]);
        let findings = lint(&write_spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn pure_program_with_no_ops_is_clean() -> anyhow::Result<()> {
        let spec = ActorSpec::default();
        let program = DoNode::pure(Value::Int(1)).and_then(s("noop"));
        let findings = lint(&spec, &program);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn spec_serde_roundtrip() -> anyhow::Result<()> {
        let spec = ActorSpec {
            name: "n".into(),
            body: DoNode::pure(Value::Null),
            declared_capabilities: vec!["perform://effect/fs/**".into()],
            budget: BudgetSpec::default(),
            finalizers: Vec::new(),
        };
        let s = serde_json::to_string(&spec)?;
        let back: ActorSpec = serde_json::from_str(&s)?;
        ensure!(spec == back, "round trip changed spec: {back:?}");
        Ok(())
    }

    #[test]
    fn lint_actor_uses_spec_body() -> anyhow::Result<()> {
        let mut spec = ActorSpec::with_capabilities("writer", ["write://state/events/**"]);
        let mut append = op("state://events/topic")?;
        append.method = "append".into();
        spec.body = DoNode::op(append);
        let findings = lint_actor(&spec);
        ensure!(findings.is_empty(), "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn lint_actor_checks_finalizers() -> anyhow::Result<()> {
        let mut spec = ActorSpec::with_capabilities("writer", ["write://state/events/**"]);
        spec.finalizers
            .push(DoNode::op(op("effect://events/emit")?));
        let findings = lint_actor(&spec);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        let finding = findings.first().context("missing finding")?;
        ensure!(
            finding.message.contains("finalizer[0]"),
            "missing finalizer context: {}",
            finding.message
        );
        Ok(())
    }

    #[test]
    fn malformed_declared_capability_is_reported_once_for_actor() -> anyhow::Result<()> {
        let mut spec = ActorSpec::with_capabilities("a", ["effect://x/post"]);
        spec.finalizers.push(DoNode::pure(Value::Null));
        let findings = lint_actor(&spec);
        ensure!(findings.len() == 1, "unexpected findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn bind_process_local_refs_rewrites_actor_spec() -> anyhow::Result<()> {
        let mut write = op("state://process/self/scratch")?;
        write.method = "write".into();
        let mut spec =
            ActorSpec::with_capabilities("worker", ["write://state/process/self/**@until=123"]);
        spec.body = DoNode::op(write);
        spec.finalizers.push(DoNode::wait_signal(Path::parse(
            "state://process/self/stop",
        )?));

        let bound = spec.bind_process_local_refs(ProcessId::new(77))?;
        ensure!(
            bound.declared_capabilities
                == vec!["write://state/process/77/**@until=123".to_string()],
            "unexpected capabilities: {:?}",
            bound.declared_capabilities
        );
        let op = bound.body.ops().first().copied().context("missing op")?;
        ensure!(
            op.target.path().to_string() == "state://process/77/scratch",
            "unexpected body target: {}",
            op.target.path()
        );
        match bound.finalizers.first().context("missing finalizer")? {
            DoNode::Wait(WaitSpec::Signal(path)) => ensure!(
                path.to_string() == "state://process/77/stop",
                "unexpected finalizer path: {path}"
            ),
            other => bail!("unexpected finalizer: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn capability_query_reports_malformed_target() -> anyhow::Result<()> {
        let spec = ActorSpec::with_capabilities("reader", ["read://state/memory/**"]);
        let err = match spec.declares_capability("read", "state://bad//path") {
            Ok(value) => bail!("malformed target unexpectedly returned {value}"),
            Err(error) => error,
        };
        ensure!(
            matches!(err, CapabilityQueryError::TargetPath { .. }),
            "unexpected error: {err:?}"
        );
        Ok(())
    }
}
