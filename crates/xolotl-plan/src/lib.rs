#![forbid(unsafe_code)]

//! Plan document compiler.
//!
//! This crate parses YAML or JSON [`Plan`] documents and lowers them to
//! [`DoNode`] programs for kernel execution.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use xolotl_graph::{DoNode, OperationTemplate, StepRef};
use xolotl_types::{
    OutputMode, Path, PathRegistry, ProcessId, ResourceName, Value, default_registry,
};

/// JSON value used by Plan documents before they are lowered to
/// [`xolotl_types::Value`].
pub type JsonValue = serde_json::Value;

/// A serializable workflow document that compiles to one [`DoNode`] program.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    /// Stable author-chosen identifier for the plan.
    pub id: String,
    /// Plan schema/version number carried by the document.
    pub version: u32,
    /// Optional human-facing summary; not used by compilation.
    #[serde(default)]
    pub description: Option<String>,
    /// Ordered root steps compiled into the program body.
    pub steps: Vec<Step>,
}

/// One Plan instruction.
///
/// Simple value/effect steps compile to `DoNode::Op`, `DoNode::Pure`, or
/// `DoNode::Use`; control steps compile to graph composition nodes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Invoke an effect Resource (`effect://…`), method `invoke`.
    Perform {
        /// Effect resource path, for example `effect://inference/infer`.
        target: String,
        /// Literal input passed to the effect driver.
        #[serde(default)]
        input: Option<JsonValue>,
    },
    /// Read the current value of a state Resource (`Value.read`).
    Read {
        /// State resource path to read.
        path: String,
        /// Local binding name for the read value. Defaults to `_`.
        #[serde(default = "default_as_name")]
        r#as: String,
    },
    /// Lower to a state-path `subscribe` operation; the installed resource must
    /// expose that method for the program to run successfully.
    Subscribe {
        /// State sequence path to subscribe to.
        path: String,
        /// Step invoked for each delivered event.
        step: StepRefSpec,
    },
    /// Write a state Resource (`Value.write` / `Sequence.append`).
    Write {
        /// State resource path to mutate.
        path: String,
        /// Value written or appended to the state resource.
        value: JsonValue,
        /// Write method selection. Defaults to [`WriteModeSpec::Set`].
        #[serde(default)]
        mode: WriteModeSpec,
    },
    /// Continue the current node with a named step reference.
    Then {
        /// Process-local continuation name.
        name: String,
        /// Optional literal argument passed to the continuation.
        #[serde(default)]
        arg: Option<JsonValue>,
    },
    /// Run a named recovery step if the current node fails.
    OnFail {
        /// Process-local recovery continuation name.
        name: String,
        /// Optional literal argument passed to the recovery continuation.
        #[serde(default)]
        arg: Option<JsonValue>,
    },
    /// Run two step sequences and collect both outcomes.
    Parallel {
        /// Left branch body.
        left: Vec<Step>,
        /// Right branch body.
        right: Vec<Step>,
    },
    /// Run two step sequences and return the first completed outcome.
    Race {
        /// Left branch body.
        left: Vec<Step>,
        /// Right branch body.
        right: Vec<Step>,
    },
    /// Bind a literal value in the local environment.
    Let {
        /// Binding name.
        name: String,
        /// Literal value bound to `name`.
        value: JsonValue,
    },
    /// Read a value from the local environment.
    Use {
        /// Binding name to resolve.
        name: String,
    },
    /// Return a literal value.
    Pure {
        /// Literal result value.
        value: JsonValue,
    },
    /// Run `body` under a different identity.
    Acting {
        /// Identity path used for the block.
        identity: String,
        /// Steps executed under `identity`.
        body: Vec<Step>,
    },
    /// Resource acquire/use/release idiom: `release` runs on success or failure.
    Bracket {
        /// Step that acquires the resource.
        acquire: Box<Step>,
        /// Steps run while the acquired resource is bound.
        body: Vec<Step>,
        /// Release step run on both success and failure paths.
        release: StepRefSpec,
    },
}

/// A process-local step reference (name + optional inline arg). The compiler
/// binds it to the caller-supplied ProcessId so the serialized Do graph carries
/// the `StepRef { process, name }` invariant explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepRefSpec {
    /// Process-local step name.
    pub name: String,
    /// Optional literal argument supplied when the step is invoked.
    #[serde(default)]
    pub arg: Option<JsonValue>,
}

fn default_as_name() -> String {
    "_".into()
}

/// State-write method selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteModeSpec {
    /// `Value.write` (set/overwrite).
    #[default]
    Set,
    /// `Sequence.append` (event publish).
    Append,
}

impl WriteModeSpec {
    fn method(self) -> &'static str {
        match self {
            WriteModeSpec::Set => "write",
            WriteModeSpec::Append => "append",
        }
    }
}

/// Errors raised while parsing, validating, or lowering a [`Plan`].
#[derive(Debug, Error)]
pub enum PlanError {
    /// A path literal failed Xolotl path parsing.
    #[error("path: {0}")]
    Path(#[from] xolotl_types::PathError),
    /// The plan did not contain any root steps.
    #[error("plan must contain at least one step")]
    Empty,
    /// A continuation-only step appeared before any current node existed.
    #[error("step {0} cannot be the first step")]
    BadFirstStep(&'static str),
    /// Two bindings use the same name in one plan.
    #[error("duplicate step name: {0}")]
    DuplicateName(String),
    /// A `${name}` binding dependency graph contains a cycle.
    #[error("reference cycle detected involving step: {0}")]
    Cycle(String),
    /// A step target path is malformed or uses the wrong scheme for its kind.
    #[error("invalid {kind} target `{target}`: {reason}")]
    Target {
        /// Step kind being validated.
        kind: &'static str,
        /// Original target/path literal from the plan.
        target: String,
        /// Validation failure detail.
        reason: String,
    },
    /// YAML decoding failed.
    #[error("yaml: {0}")]
    Yaml(String),
    /// JSON decoding or `DoNode` serialization failed.
    #[error("json: {0}")]
    Json(String),
}

/// Compile a Plan into a [`DoNode`] program for `process`.
pub fn compile_for(process: ProcessId, plan: &Plan) -> Result<DoNode, PlanError> {
    if plan.steps.is_empty() {
        return Err(PlanError::Empty);
    }
    validate_plan(plan)?;
    compile_steps(process, &plan.steps)
}

/// Static validation pass run before lowering.
///
/// Rejects: duplicate explicit `let` binding names, and reference cycles formed
/// by steps that bind a name and reference another binding via `${name}`
/// placeholders in their args. The empty-plan and bad-first-step checks live in
/// [`compile`] / [`step_to_do`] respectively.
fn validate_plan(plan: &Plan) -> Result<(), PlanError> {
    let mut all = Vec::new();
    collect_all_steps(&plan.steps, &mut all);
    let path_registry = default_registry();

    // Reject duplicate `let` binding names across the whole step tree.
    let mut seen = std::collections::BTreeSet::new();
    for step in &all {
        if let Step::Let { name, .. } = step
            && !seen.insert(name.clone())
        {
            return Err(PlanError::DuplicateName(name.clone()));
        }
    }

    // Operation targets must match their step kind; this catches
    // resource-path/capability confusion before lowering.
    for step in &all {
        validate_step_target(step, &path_registry)?;
    }

    // Acting identities must be real identity paths, not bare schemes.
    for step in &all {
        if let Step::Acting { identity, .. } = step {
            validate_identity_literal("acting identity", identity)?;
        }
    }

    // Build binding reference edges and reject cycles among `${...}` links.
    let binders: std::collections::BTreeSet<String> = all
        .iter()
        .flat_map(|s| step_binds(s))
        .filter(|n| n != "_")
        .collect();
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for step in &all {
        let binds = step_binds(step);
        if binds.is_empty() {
            continue;
        }
        let refs = step_refs(step);
        for b in binds {
            if b == "_" {
                continue;
            }
            for r in &refs {
                if binders.contains(r) {
                    graph.entry(b.clone()).or_default().push(r.clone());
                }
            }
        }
    }
    detect_cycle(&graph)
}

fn validate_step_target(step: &Step, registry: &PathRegistry) -> Result<(), PlanError> {
    match step {
        Step::Perform { target, .. } => validate_target("perform", target, "effect", registry),
        Step::Read { path, .. } => validate_target("read", path, "state", registry),
        Step::Subscribe { path, .. } => validate_target("subscribe", path, "state", registry),
        Step::Write { path, .. } => validate_target("write", path, "state", registry),
        _ => Ok(()),
    }
}

fn validate_target(
    kind: &'static str,
    literal: &str,
    expected_scheme: &str,
    registry: &PathRegistry,
) -> Result<(), PlanError> {
    let path = Path::parse(literal).map_err(|e| PlanError::Target {
        kind,
        target: literal.to_string(),
        reason: e.to_string(),
    })?;
    if path.scheme() != expected_scheme {
        return Err(PlanError::Target {
            kind,
            target: literal.to_string(),
            reason: format!(
                "expected {expected_scheme}:// target, got {}://",
                path.scheme()
            ),
        });
    }
    registry.validate(&path).map_err(|e| PlanError::Target {
        kind,
        target: literal.to_string(),
        reason: e.to_string(),
    })
}

fn validate_identity_literal(kind: &'static str, literal: &str) -> Result<(), PlanError> {
    let path = Path::parse(literal).map_err(|e| PlanError::Target {
        kind,
        target: literal.to_string(),
        reason: e.to_string(),
    })?;
    if path.segments().is_empty() {
        return Err(PlanError::Target {
            kind,
            target: literal.to_string(),
            reason: "identity path must include at least one segment".into(),
        });
    }
    Ok(())
}

/// DFS three-color cycle detection over the binding dependency graph.
fn detect_cycle(graph: &BTreeMap<String, Vec<String>>) -> Result<(), PlanError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        InProgress,
        Done,
    }
    let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();
    // Iterative DFS to avoid stack overflow on adversarial input.
    for root in graph.keys() {
        if marks.contains_key(root.as_str()) {
            continue;
        }
        let mut stack: Vec<(&str, bool)> = vec![(root.as_str(), false)];
        while let Some((node, exiting)) = stack.pop() {
            if exiting {
                marks.insert(node, Mark::Done);
                continue;
            }
            match marks.get(node) {
                Some(Mark::Done) => continue,
                Some(Mark::InProgress) => {}
                None => {}
            }
            marks.insert(node, Mark::InProgress);
            stack.push((node, true));
            if let Some(succs) = graph.get(node) {
                for s in succs {
                    match marks.get(s.as_str()) {
                        Some(Mark::InProgress) => return Err(PlanError::Cycle(s.clone())),
                        Some(Mark::Done) => {}
                        None => stack.push((s.as_str(), false)),
                    }
                }
            }
        }
    }
    Ok(())
}

/// Flatten the step tree (recursing into nested bodies) for validation.
fn collect_all_steps<'a>(steps: &'a [Step], out: &mut Vec<&'a Step>) {
    for step in steps {
        out.push(step);
        match step {
            Step::Parallel { left, right } | Step::Race { left, right } => {
                collect_all_steps(left, out);
                collect_all_steps(right, out);
            }
            Step::Acting { body, .. } => {
                collect_all_steps(body, out);
            }
            Step::Bracket { acquire, body, .. } => {
                collect_all_steps(std::slice::from_ref(acquire.as_ref()), out);
                collect_all_steps(body, out);
            }
            _ => {}
        }
    }
}

/// Names a step binds into the local environment (`let`, `read … as`).
fn step_binds(step: &Step) -> Vec<String> {
    match step {
        Step::Let { name, .. } => vec![name.clone()],
        Step::Read { r#as, .. } => vec![r#as.clone()],
        _ => Vec::new(),
    }
}

/// Names a step references — via `${name}` placeholders in its args, or via an
/// explicit `Use`. Used for cycle detection and the auto-parallelism check.
fn step_refs(step: &Step) -> Vec<String> {
    match step {
        Step::Perform { input, .. } => input.as_ref().map(extract_refs).unwrap_or_default(),
        Step::Write { value, .. } | Step::Let { value, .. } | Step::Pure { value } => {
            extract_refs(value)
        }
        Step::Use { name } => vec![name.clone()],
        Step::Then { arg, .. } | Step::OnFail { arg, .. } => {
            arg.as_ref().map(extract_refs).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Scan a JSON value for `${name}` placeholders, returning each referenced name
/// The Plan model otherwise binds via `let`/`use`; this lets
/// inline args express data dependencies for ordering and parallelism.
fn extract_refs(value: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    collect_refs(value, &mut out);
    out
}

fn collect_refs(value: &JsonValue, out: &mut Vec<String>) {
    match value {
        JsonValue::String(s) => scan_placeholders(s, out),
        JsonValue::Array(xs) => xs.iter().for_each(|x| collect_refs(x, out)),
        JsonValue::Object(m) => m.values().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

/// Pull every `${...}` token out of a string. A name runs until the closing `}`.
fn scan_placeholders(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(end_rel) = s[i + 2..].find('}')
        {
            let name = &s[i + 2..i + 2 + end_rel];
            if !name.is_empty() {
                out.push(name.to_string());
            }
            i = i + 2 + end_rel + 1;
            continue;
        }
        i += 1;
    }
}

/// Whether two adjacent value steps carry no data dependency in either
/// direction, so they may run in parallel.
fn independent(a: &Step, b: &Step) -> bool {
    let (ba, bb) = (step_binds(a), step_binds(b));
    let (ra, rb) = (step_refs(a), step_refs(b));
    let intersects = |xs: &[String], ys: &[String]| xs.iter().any(|x| ys.contains(x));
    !intersects(&rb, &ba) && !intersects(&ra, &bb)
}

/// Whether a step is a plain value step eligible for auto-parallel pairing.
/// Control steps and compound steps are never auto-paired.
fn is_mergeable(step: &Step) -> bool {
    matches!(
        step,
        Step::Perform { .. }
            | Step::Read { .. }
            | Step::Write { .. }
            | Step::Let { .. }
            | Step::Use { .. }
            | Step::Pure { .. }
    )
}

/// Compile a sequence of steps, threading `then`/`on_fail` as continuations and
/// binding other steps in sequence via `Let`. Adjacent independent value steps
/// are paired into `Both` for parallelism.
///
/// Parallel pairing is local and left-to-right.
fn compile_steps(process: ProcessId, steps: &[Step]) -> Result<DoNode, PlanError> {
    if steps.is_empty() {
        return Err(PlanError::Empty);
    }
    let mut current: Option<DoNode> = None;
    let mut i = 0;
    while i < steps.len() {
        let step = &steps[i];
        match step {
            Step::Then { name, arg } => {
                let c = current.ok_or(PlanError::BadFirstStep("then"))?;
                current = Some(c.and_then(step_ref(process, name, arg)));
                i += 1;
            }
            Step::OnFail { name, arg } => {
                let c = current.ok_or(PlanError::BadFirstStep("on_fail"))?;
                current = Some(c.or_else(step_ref(process, name, arg)));
                i += 1;
            }
            other => {
                // Try to pair with the next step for parallel execution.
                let unit = match steps.get(i + 1) {
                    Some(next)
                        if is_mergeable(other)
                            && is_mergeable(next)
                            && independent(other, next) =>
                    {
                        i += 2;
                        DoNode::both(step_to_do(process, other)?, step_to_do(process, next)?)
                    }
                    _ => {
                        i += 1;
                        step_to_do(process, other)?
                    }
                };
                current = Some(match current {
                    None => unit,
                    Some(c) => {
                        let n = c.size();
                        DoNode::r#let(format!("_step_{n}"), c, unit)
                    }
                });
            }
        }
    }
    current.ok_or(PlanError::Empty)
}

fn step_ref(process: ProcessId, name: &str, arg: &Option<JsonValue>) -> StepRef {
    let sr = StepRef::new(process, name);
    match arg {
        Some(a) => sr.with_arg(json_to_value(a)),
        None => sr,
    }
}

/// One operation template targeting `path`'s Resource via `method`.
fn op(path: &str, method: &str, input: Option<Value>) -> Result<DoNode, PlanError> {
    Ok(DoNode::Op(OperationTemplate {
        target: ResourceName::new(Path::parse(path)?),
        method: method.to_string(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: input,
    }))
}

fn step_to_do(process: ProcessId, step: &Step) -> Result<DoNode, PlanError> {
    Ok(match step {
        Step::Perform { target, input } => op(target, "invoke", input.as_ref().map(json_to_value))?,
        Step::Read { path, .. } => op(path, "read", None)?,
        Step::Subscribe { path, step } => {
            // The handling step is carried as literal input so a compatible
            // subscribe driver can wire delivery.
            let mut m = BTreeMap::new();
            m.insert("step".into(), Value::Str(step.name.clone()));
            if let Some(a) = &step.arg {
                m.insert("arg".into(), json_to_value(a));
            }
            op(path, "subscribe", Some(Value::Map(m)))?
        }
        Step::Write { path, value, mode } => op(path, mode.method(), Some(json_to_value(value)))?,
        Step::Then { .. } => return Err(PlanError::BadFirstStep("then")),
        Step::OnFail { .. } => return Err(PlanError::BadFirstStep("on_fail")),
        Step::Parallel { left, right } => DoNode::both(
            compile_steps(process, left)?,
            compile_steps(process, right)?,
        ),
        Step::Race { left, right } => DoNode::race(
            compile_steps(process, left)?,
            compile_steps(process, right)?,
        ),
        Step::Let { name, value } => DoNode::r#let(
            name.clone(),
            DoNode::pure(json_to_value(value)),
            DoNode::use_(name.clone()),
        ),
        Step::Use { name } => DoNode::use_(name.clone()),
        Step::Pure { value } => DoNode::pure(json_to_value(value)),
        Step::Acting { identity, body } => {
            DoNode::acting(Path::parse(identity)?, compile_steps(process, body)?)
        }
        Step::Bracket {
            acquire,
            body,
            release,
        } => {
            let acquire_node = step_to_do(process, acquire)?;
            let body_node = compile_steps(process, body)?;
            let release_ref = step_ref(process, &release.name, &release.arg);
            let released_on_success = body_node.and_then(release_ref.clone());
            let released_on_failure = released_on_success.or_else(release_ref);
            DoNode::r#let("_resource", acquire_node, released_on_failure)
        }
    })
}

fn json_to_value(j: &JsonValue) -> Value {
    match j {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(b) => Value::Bool(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(xolotl_types::FloatBits(f))
            } else {
                Value::Null
            }
        }
        JsonValue::String(s) => Value::Str(s.clone()),
        JsonValue::Array(xs) => Value::List(xs.iter().map(json_to_value).collect()),
        JsonValue::Object(m) => {
            let mut bm = BTreeMap::new();
            for (k, v) in m {
                bm.insert(k.clone(), json_to_value(v));
            }
            Value::Map(bm)
        }
    }
}

/// Parse a YAML Plan document.
pub fn parse_yaml(src: &str) -> Result<Plan, PlanError> {
    yaml_serde::from_str(src).map_err(|e| PlanError::Yaml(e.to_string()))
}

/// Parse a JSON Plan document.
pub fn parse_json(src: &str) -> Result<Plan, PlanError> {
    serde_json::from_str(src).map_err(|e| PlanError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};

    fn plan(steps: Vec<Step>) -> Plan {
        Plan {
            id: "p".into(),
            version: 1,
            description: None,
            steps,
        }
    }

    fn pid() -> ProcessId {
        ProcessId::new(1)
    }

    fn compile_test(plan: &Plan) -> Result<DoNode, PlanError> {
        compile_for(pid(), plan)
    }

    #[test]
    fn compile_single_perform() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Perform {
            target: "effect://x/post".into(),
            input: Some(serde_json::json!("hello")),
        }]))?;
        match node {
            DoNode::Op(t) => {
                ensure!(
                    t.target.path().to_string() == "effect://x/post",
                    "unexpected target: {}",
                    t.target.path()
                );
                ensure!(t.method == "invoke", "unexpected method: {}", t.method);
                ensure!(
                    t.literal_input == Some(Value::Str("hello".into())),
                    "unexpected input: {:?}",
                    t.literal_input
                );
            }
            other => bail!("expected operation node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn read_maps_to_value_read() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Read {
            path: "state://memory/alice".into(),
            r#as: "v".into(),
        }]))?;
        match node {
            DoNode::Op(t) => ensure!(t.method == "read", "unexpected method: {}", t.method),
            other => bail!("expected operation node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn write_set_vs_append() -> anyhow::Result<()> {
        let set = compile_test(&plan(vec![Step::Write {
            path: "state://x".into(),
            value: serde_json::json!(1),
            mode: WriteModeSpec::Set,
        }]))?;
        match set {
            DoNode::Op(t) => ensure!(t.method == "write", "unexpected method: {}", t.method),
            other => bail!("expected operation node, got {other:?}"),
        }
        let app = compile_test(&plan(vec![Step::Write {
            path: "state://log".into(),
            value: serde_json::json!("e"),
            mode: WriteModeSpec::Append,
        }]))?;
        match app {
            DoNode::Op(t) => ensure!(t.method == "append", "unexpected method: {}", t.method),
            other => bail!("expected operation node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn compile_chain_ends_in_or_else() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Perform {
                target: "effect://inference/infer".into(),
                input: None,
            },
            Step::Then {
                name: "post".into(),
                arg: None,
            },
            Step::OnFail {
                name: "ack".into(),
                arg: None,
            },
        ]))?;
        ensure!(
            matches!(node, DoNode::OrElse { .. }),
            "expected OrElse node, got {node:?}"
        );
        Ok(())
    }

    #[test]
    fn empty_plan_errors() -> anyhow::Result<()> {
        ensure!(
            matches!(compile_test(&plan(vec![])), Err(PlanError::Empty)),
            "empty plan should be rejected"
        );
        Ok(())
    }

    #[test]
    fn parallel_and_race_compile() -> anyhow::Result<()> {
        let par = compile_test(&plan(vec![Step::Parallel {
            left: vec![Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            }],
            right: vec![Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            }],
        }]))?;
        ensure!(
            matches!(par, DoNode::Both(_, _)),
            "expected Both node, got {par:?}"
        );
        let race = compile_test(&plan(vec![Step::Race {
            left: vec![Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            }],
            right: vec![Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            }],
        }]))?;
        ensure!(
            matches!(race, DoNode::Race(_, _)),
            "expected Race node, got {race:?}"
        );
        Ok(())
    }

    #[test]
    fn acting_compiles() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Acting {
            identity: "process://alice".into(),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]))?;
        ensure!(
            matches!(node, DoNode::Acting { .. }),
            "expected Acting node, got {node:?}"
        );
        Ok(())
    }

    #[test]
    fn acting_identity_must_be_shaped_path() -> anyhow::Result<()> {
        let err = compile_test(&plan(vec![Step::Acting {
            identity: "alice".into(),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]));
        ensure!(
            matches!(
            err,
            Err(PlanError::Target { kind, target, .. })
                if kind == "acting identity" && target == "alice"
            ),
            "acting identity should be rejected"
        );
        Ok(())
    }

    #[test]
    fn subscribe_carries_step_in_input() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Subscribe {
            path: "state://events/chat".into(),
            step: StepRefSpec {
                name: "react".into(),
                arg: None,
            },
        }]))?;
        match node {
            DoNode::Op(t) => {
                ensure!(t.method == "subscribe", "unexpected method: {}", t.method);
                ensure!(
                    matches!(t.literal_input, Some(Value::Map(_))),
                    "unexpected input: {:?}",
                    t.literal_input
                );
            }
            other => bail!("expected operation node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn bracket_compiles_to_let_with_release() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Bracket {
            acquire: Box::new(Step::Perform {
                target: "effect://lock/take".into(),
                input: None,
            }),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
            release: StepRefSpec {
                name: "release".into(),
                arg: None,
            },
        }]))?;
        match node {
            DoNode::Let { body, .. } => ensure!(
                matches!(*body, DoNode::OrElse { .. }),
                "expected OrElse release body, got {body:?}"
            ),
            other => bail!("expected Let node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn yaml_round_trip_and_compile() -> anyhow::Result<()> {
        let src = r#"
id: hi
version: 1
steps:
  - kind: perform
    target: "effect://x/post"
    input: "hello"
"#;
        let plan = parse_yaml(src)?;
        ensure!(plan.id == "hi", "unexpected plan id: {}", plan.id);
        compile_test(&plan)?;
        Ok(())
    }

    #[test]
    fn json_value_to_kernel_value() -> anyhow::Result<()> {
        let v = json_to_value(&serde_json::json!({"n": 7, "ok": true, "list": [1, 2]}));
        match v {
            Value::Map(m) => {
                ensure!(
                    m.get("n").context("missing n")? == &Value::Int(7),
                    "unexpected n"
                );
                ensure!(
                    m.get("ok").context("missing ok")? == &Value::Bool(true),
                    "unexpected ok"
                );
                ensure!(
                    matches!(m.get("list").context("missing list")?, Value::List(_)),
                    "unexpected list"
                );
            }
            other => bail!("expected map value, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn duplicate_let_name_rejected() -> anyhow::Result<()> {
        let err = compile_test(&plan(vec![
            Step::Let {
                name: "x".into(),
                value: serde_json::json!(1),
            },
            Step::Let {
                name: "x".into(),
                value: serde_json::json!(2),
            },
        ]));
        ensure!(
            matches!(err, Err(PlanError::DuplicateName(n)) if n == "x"),
            "duplicate name should be rejected"
        );
        Ok(())
    }

    #[test]
    fn extract_refs_finds_placeholders() -> anyhow::Result<()> {
        let v = serde_json::json!({"a": "${first}", "b": ["x", "${second}y"]});
        let mut refs = extract_refs(&v);
        refs.sort();
        ensure!(
            refs == vec!["first".to_string(), "second".to_string()],
            "unexpected refs: {refs:?}"
        );
        ensure!(
            extract_refs(&serde_json::json!("no refs here")).is_empty(),
            "non-placeholder string should not produce refs"
        );
        Ok(())
    }

    #[test]
    fn reference_cycle_rejected() -> anyhow::Result<()> {
        let err = compile_test(&plan(vec![
            Step::Let {
                name: "a".into(),
                value: serde_json::json!("${b}"),
            },
            Step::Let {
                name: "b".into(),
                value: serde_json::json!("${a}"),
            },
        ]));
        ensure!(
            matches!(err, Err(PlanError::Cycle(_))),
            "cycle should be rejected"
        );
        Ok(())
    }

    #[test]
    fn independent_steps_compile_to_both() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            },
            Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            },
        ]))?;
        ensure!(
            matches!(node, DoNode::Both(_, _)),
            "expected Both node, got {node:?}"
        );
        Ok(())
    }

    #[test]
    fn dependent_steps_stay_sequential() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Let {
                name: "a".into(),
                value: serde_json::json!(1),
            },
            Step::Perform {
                target: "effect://x/b".into(),
                input: Some(serde_json::json!("${a}")),
            },
        ]))?;
        ensure!(
            matches!(node, DoNode::Let { .. }),
            "expected Let node, got {node:?}"
        );
        Ok(())
    }

    #[test]
    fn three_independent_steps_pairwise_parallel() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            },
            Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            },
            Step::Perform {
                target: "effect://x/c".into(),
                input: None,
            },
        ]))?;
        match node {
            DoNode::Let { value, body, .. } => {
                ensure!(
                    matches!(*value, DoNode::Both(_, _)),
                    "expected Both value, got {value:?}"
                );
                ensure!(
                    matches!(*body, DoNode::Op(_)),
                    "expected Op body, got {body:?}"
                );
            }
            other => bail!("expected Let wrapping Both, got {other:?}"),
        }
        Ok(())
    }
}
