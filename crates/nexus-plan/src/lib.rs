#![forbid(unsafe_code)]

//! `nexus-plan` — Plan compiler.
//!
//! A *Plan* is a YAML/JSON document describing a goal-directed pipeline of
//! steps. The compiler turns a Plan into a [`DoNode`](nexus_graph::DoNode),
//! which the kernel compiles to an `ExecutionGraph` and runs (§13).
//!
//! Every step maps to the Direction-C primitives. There is no `Op` enum any
//! more: state and effect access are both `Operation`s on a Resource named by
//! its `Path`, distinguished by the method (`read`/`write`/`append`/`subscribe`
//! for `state://`, `invoke` for `effect://`).
//!
//! | step kind   | DoNode mapping                                              |
//! |-------------|-------------------------------------------------------------|
//! | `perform`   | `Op(OperationTemplate{ method: "invoke" })`                 |
//! | `read`      | `Op(OperationTemplate{ method: "read" })`                   |
//! | `subscribe` | `Op(OperationTemplate{ method: "subscribe" })`              |
//! | `write`     | `Op(OperationTemplate{ method: "write"/"append" })`         |
//! | `then`      | `AndThen { d, then: StepRef }`                              |
//! | `on_fail`   | `OrElse { d, or: StepRef }`                                 |
//! | `parallel`  | `Both(left, right)`                                         |
//! | `race`      | `Race(left, right)`                                         |
//! | `let`/`use` | `Let { name, value, body }` / `Use(name)`                   |
//! | `pure`      | `Pure(value)`                                               |
//! | `acting`    | `Acting { identity, body }`                                 |
//! | `spawn`     | `Op(OperationTemplate{ target: effect://kernel/spawn })`    |
//! | `bracket`   | acquire → (body then release) or-else release               |

use nexus_graph::{DoNode, OperationTemplate, StepRef};
use nexus_types::{
    Capability, OutputMode, Path, PathRegistry, ProcessId, ResourceName, Value, default_registry,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub type JsonValue = serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub version: u32,
    #[serde(default)]
    pub description: Option<String>,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Invoke an effect Resource (`effect://…`), method `invoke`.
    Perform {
        target: String,
        #[serde(default)]
        input: Option<JsonValue>,
    },
    /// Read the current value of a state Resource (`Value.read`).
    Read {
        path: String,
        #[serde(default = "default_as_name")]
        r#as: String,
    },
    /// Subscribe to a Sequence Resource (`Sequence.subscribe`); the body step
    /// handles each event.
    Subscribe {
        path: String,
        step: StepRefSpec,
    },
    /// Write a state Resource (`Value.write` / `Sequence.append`).
    Write {
        path: String,
        value: JsonValue,
        #[serde(default)]
        mode: WriteModeSpec,
    },
    Then {
        name: String,
        #[serde(default)]
        arg: Option<JsonValue>,
    },
    OnFail {
        name: String,
        #[serde(default)]
        arg: Option<JsonValue>,
    },
    Parallel {
        left: Vec<Step>,
        right: Vec<Step>,
    },
    Race {
        left: Vec<Step>,
        right: Vec<Step>,
    },
    Let {
        name: String,
        value: JsonValue,
    },
    Use {
        name: String,
    },
    Pure {
        value: JsonValue,
    },
    /// Run `body` under a different identity (`act-as`, §13.2).
    Acting {
        identity: String,
        body: Vec<Step>,
    },
    /// Spawn a child Process: a kernel Operation on `effect://kernel/spawn`.
    Spawn {
        #[serde(default)]
        identity: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
        body: Vec<Step>,
    },
    /// Resource acquire/use/release idiom: `release` runs on success or failure.
    Bracket {
        acquire: Box<Step>,
        body: Vec<Step>,
        release: StepRefSpec,
    },
}

/// A process-local step reference (name + optional inline arg). The compiler
/// binds it to the caller-supplied ProcessId so the serialized Do graph carries
/// the §13.3 `StepRef { process, name }` invariant explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepRefSpec {
    pub name: String,
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

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("path: {0}")]
    Path(#[from] nexus_types::PathError),
    #[error("plan must contain at least one step")]
    Empty,
    #[error("step {0} cannot be the first step")]
    BadFirstStep(&'static str),
    #[error("duplicate step name: {0}")]
    DuplicateName(String),
    #[error("reference cycle detected involving step: {0}")]
    Cycle(String),
    #[error("invalid capability literal `{0}`: {1}")]
    Capability(String, String),
    #[error("invalid {kind} target `{target}`: {reason}")]
    Target {
        kind: &'static str,
        target: String,
        reason: String,
    },
    #[error("yaml: {0}")]
    Yaml(String),
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

/// Static validation pass run before lowering (§20.4: "校验 … 引用环").
///
/// Rejects: duplicate explicit `let` binding names, and reference cycles formed
/// by steps that bind a name and reference another binding via `${name}`
/// placeholders in their args. The empty-plan and bad-first-step checks live in
/// [`compile`] / [`step_to_do`] respectively.
fn validate_plan(plan: &Plan) -> Result<(), PlanError> {
    let mut all = Vec::new();
    collect_all_steps(&plan.steps, &mut all);
    let path_registry = default_registry();

    // 1. Duplicate `let` binding names (across the whole step tree).
    let mut seen = std::collections::BTreeSet::new();
    for step in &all {
        if let Step::Let { name, .. } = step
            && !seen.insert(name.clone())
        {
            return Err(PlanError::DuplicateName(name.clone()));
        }
    }

    // 2. Operation targets must match their step kind (§20.4 target validation).
    //    This catches resource-path/capability confusion before lowering.
    for step in &all {
        validate_step_target(step, &path_registry)?;
    }

    // 3. Acting/spawn identities must be real identity paths, not bare schemes.
    for step in &all {
        match step {
            Step::Acting { identity, .. } => {
                validate_identity_literal("acting identity", identity)?
            }
            Step::Spawn {
                identity: Some(identity),
                ..
            } => validate_identity_literal("spawn identity", identity)?,
            _ => {}
        }
    }

    // 4. Spawn capability ceilings must use §21.1 capability literals, not
    //    resource paths. The kernel spawn path will attenuate these again, but
    //    Plan compilation is the first fail-closed boundary (§20.4).
    for step in &all {
        if let Step::Spawn { capabilities, .. } = step {
            for capability in capabilities {
                let parsed = Capability::parse(capability)
                    .map_err(|e| PlanError::Capability(capability.clone(), e.to_string()))?;
                validate_capability_scheme(capability, &parsed)?;
            }
        }
    }

    // 5. Reference cycle among `${...}`-linked bindings. Build edges
    //    binding -> referenced-binding, then DFS for a back edge.
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

fn validate_capability_scheme(literal: &str, capability: &Capability) -> Result<(), PlanError> {
    let Some(expected_scheme) = expected_scheme_for_capability_verb(&capability.verb) else {
        return Ok(());
    };
    if capability.scheme == expected_scheme || capability.scheme == "*" || capability.scheme == "**"
    {
        return Ok(());
    }
    Err(PlanError::Capability(
        literal.to_string(),
        format!(
            "`{}` capability must target {}://, got {}://",
            capability.verb, expected_scheme, capability.scheme
        ),
    ))
}

fn expected_scheme_for_capability_verb(verb: &str) -> Option<&'static str> {
    match verb {
        "perform" => Some("effect"),
        "read" | "write" | "subscribe" => Some("state"),
        "spawn" | "act-as" => Some("process"),
        "*" => None,
        _ => None,
    }
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
            Step::Acting { body, .. } | Step::Spawn { body, .. } => {
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
/// (§20.4 ref syntax). The Plan model otherwise binds via `let`/`use`; this lets
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
/// direction, so they may run in parallel (§20.4: "无依赖→Both 并行").
fn independent(a: &Step, b: &Step) -> bool {
    let (ba, bb) = (step_binds(a), step_binds(b));
    let (ra, rb) = (step_refs(a), step_refs(b));
    let intersects = |xs: &[String], ys: &[String]| xs.iter().any(|x| ys.contains(x));
    !intersects(&rb, &ba) && !intersects(&ra, &bb)
}

/// Whether a step is a plain value step eligible for auto-parallel pairing.
/// Control steps (`then`/`on_fail`) and compound steps (parallel/race/acting/
/// spawn/bracket/subscribe) are never auto-paired — conservative by design.
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
/// are paired into `Both` for parallelism (§20.4).
///
/// Limitation vs the full design: parallelism is **pairwise and greedy
/// left-to-right**, not a full topological reorder of the whole step list. A run
/// of three independent steps `[A, B, C]` becomes `Let(Both(A, B), C)`, not a
/// 3-way fan-out. This is the conservative subset called for in the task.
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
            // Subscribe is a Sequence.subscribe Operation; the handling step is
            // carried as the literal input so the driver can wire delivery.
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
        Step::Spawn {
            identity,
            capabilities,
            body,
        } => {
            // Spawn is a kernel Operation; the child program + start record are
            // the operation input. The body compiles to a Do<A> carried inline.
            let mut m = BTreeMap::new();
            if let Some(id) = identity {
                m.insert("identity".into(), Value::Str(id.clone()));
            }
            m.insert(
                "capabilities".into(),
                Value::List(capabilities.iter().map(|c| Value::Str(c.clone())).collect()),
            );
            // Serialize the child program so the kernel spawn driver can compile
            // and run it under the new Process.
            let child = compile_steps(process, body)?;
            let child_json =
                serde_json::to_string(&child).map_err(|e| PlanError::Json(e.to_string()))?;
            m.insert("program".into(), Value::Str(child_json));
            op("effect://kernel/spawn", "invoke", Some(Value::Map(m)))?
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
                Value::Float(nexus_types::FloatBits(f))
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

pub fn parse_yaml(src: &str) -> Result<Plan, PlanError> {
    yaml_serde::from_str(src).map_err(|e| PlanError::Yaml(e.to_string()))
}

pub fn parse_json(src: &str) -> Result<Plan, PlanError> {
    serde_json::from_str(src).map_err(|e| PlanError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn compile_single_perform() {
        let node = compile_test(&plan(vec![Step::Perform {
            target: "effect://x/post".into(),
            input: Some(serde_json::json!("hello")),
        }]))
        .unwrap();
        match node {
            DoNode::Op(t) => {
                assert_eq!(t.target.path().to_string(), "effect://x/post");
                assert_eq!(t.method, "invoke");
                assert_eq!(t.literal_input, Some(Value::Str("hello".into())));
            }
            _ => panic!("wrong node"),
        }
    }

    #[test]
    fn read_maps_to_value_read() {
        let node = compile_test(&plan(vec![Step::Read {
            path: "state://memory/alice".into(),
            r#as: "v".into(),
        }]))
        .unwrap();
        match node {
            DoNode::Op(t) => assert_eq!(t.method, "read"),
            _ => panic!(),
        }
    }

    #[test]
    fn write_set_vs_append() {
        let set = compile_test(&plan(vec![Step::Write {
            path: "state://x".into(),
            value: serde_json::json!(1),
            mode: WriteModeSpec::Set,
        }]))
        .unwrap();
        match set {
            DoNode::Op(t) => assert_eq!(t.method, "write"),
            _ => panic!(),
        }
        let app = compile_test(&plan(vec![Step::Write {
            path: "state://log".into(),
            value: serde_json::json!("e"),
            mode: WriteModeSpec::Append,
        }]))
        .unwrap();
        match app {
            DoNode::Op(t) => assert_eq!(t.method, "append"),
            _ => panic!(),
        }
    }

    #[test]
    fn compile_chain_ends_in_or_else() {
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
        ]))
        .unwrap();
        assert!(matches!(node, DoNode::OrElse { .. }));
    }

    #[test]
    fn empty_plan_errors() {
        assert!(matches!(compile_test(&plan(vec![])), Err(PlanError::Empty)));
    }

    #[test]
    fn parallel_and_race_compile() {
        let par = compile_test(&plan(vec![Step::Parallel {
            left: vec![Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            }],
            right: vec![Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            }],
        }]))
        .unwrap();
        assert!(matches!(par, DoNode::Both(_, _)));
        let race = compile_test(&plan(vec![Step::Race {
            left: vec![Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            }],
            right: vec![Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            }],
        }]))
        .unwrap();
        assert!(matches!(race, DoNode::Race(_, _)));
    }

    #[test]
    fn acting_compiles() {
        let node = compile_test(&plan(vec![Step::Acting {
            identity: "process://alice".into(),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]))
        .unwrap();
        assert!(matches!(node, DoNode::Acting { .. }));
    }

    #[test]
    fn acting_identity_must_be_shaped_path() {
        let err = compile_test(&plan(vec![Step::Acting {
            identity: "alice".into(),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]));
        assert!(matches!(
            err,
            Err(PlanError::Target { kind, target, .. })
                if kind == "acting identity" && target == "alice"
        ));
    }

    #[test]
    fn spawn_targets_kernel_resource() {
        let node = compile_test(&plan(vec![Step::Spawn {
            identity: Some("process://child".into()),
            capabilities: vec!["perform://effect/x/post".into()],
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]))
        .unwrap();
        match node {
            DoNode::Op(t) => assert_eq!(t.target.path().to_string(), "effect://kernel/spawn"),
            _ => panic!(),
        }
    }

    #[test]
    fn spawn_capabilities_must_be_canonical_literals() {
        let bad = plan(vec![Step::Spawn {
            identity: Some("process://child".into()),
            capabilities: vec!["effect://x/post".into()],
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]);
        assert!(matches!(
            compile_test(&bad),
            Err(PlanError::Capability(literal, _)) if literal == "effect://x/post"
        ));

        let good = plan(vec![Step::Spawn {
            identity: Some("process://child".into()),
            capabilities: vec!["perform://effect/x/post".into()],
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]);
        compile_test(&good).unwrap();
    }

    #[test]
    fn spawn_identity_must_be_shaped_path() {
        let bad = plan(vec![Step::Spawn {
            identity: Some("child".into()),
            capabilities: vec!["perform://effect/x/post".into()],
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]);
        assert!(matches!(
            compile_test(&bad),
            Err(PlanError::Target { kind, target, .. })
                if kind == "spawn identity" && target == "child"
        ));
    }

    #[test]
    fn subscribe_carries_step_in_input() {
        let node = compile_test(&plan(vec![Step::Subscribe {
            path: "state://chat/events".into(),
            step: StepRefSpec {
                name: "react".into(),
                arg: None,
            },
        }]))
        .unwrap();
        match node {
            DoNode::Op(t) => {
                assert_eq!(t.method, "subscribe");
                assert!(matches!(t.literal_input, Some(Value::Map(_))));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bracket_compiles_to_let_with_release() {
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
        }]))
        .unwrap();
        match node {
            DoNode::Let { body, .. } => assert!(matches!(*body, DoNode::OrElse { .. })),
            _ => panic!("expected Let"),
        }
    }

    #[test]
    fn yaml_round_trip_and_compile() {
        let src = r#"
id: hi
version: 1
steps:
  - kind: perform
    target: "effect://x/post"
    input: "hello"
"#;
        let plan = parse_yaml(src).unwrap();
        assert_eq!(plan.id, "hi");
        compile_test(&plan).unwrap();
    }

    #[test]
    fn json_value_to_kernel_value() {
        let v = json_to_value(&serde_json::json!({"n": 7, "ok": true, "list": [1, 2]}));
        match v {
            Value::Map(m) => {
                assert_eq!(m.get("n").unwrap(), &Value::Int(7));
                assert_eq!(m.get("ok").unwrap(), &Value::Bool(true));
                assert!(matches!(m.get("list").unwrap(), Value::List(_)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn duplicate_let_name_rejected() {
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
        assert!(matches!(err, Err(PlanError::DuplicateName(n)) if n == "x"));
    }

    #[test]
    fn extract_refs_finds_placeholders() {
        let v = serde_json::json!({"a": "${first}", "b": ["x", "${second}y"]});
        let mut refs = extract_refs(&v);
        refs.sort();
        assert_eq!(refs, vec!["first".to_string(), "second".to_string()]);
        assert!(extract_refs(&serde_json::json!("no refs here")).is_empty());
    }

    #[test]
    fn reference_cycle_rejected() {
        // a -> b (a's value references ${b}) and b -> a forms a cycle.
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
        assert!(matches!(err, Err(PlanError::Cycle(_))));
    }

    #[test]
    fn independent_steps_compile_to_both() {
        // Two performs with no data dependency → Both (auto-parallelism, §20.4).
        let node = compile_test(&plan(vec![
            Step::Perform {
                target: "effect://x/a".into(),
                input: None,
            },
            Step::Perform {
                target: "effect://x/b".into(),
                input: None,
            },
        ]))
        .unwrap();
        assert!(matches!(node, DoNode::Both(_, _)));
    }

    #[test]
    fn dependent_steps_stay_sequential() {
        // B references ${a}, so it must run after A → stays a sequential Let.
        let node = compile_test(&plan(vec![
            Step::Let {
                name: "a".into(),
                value: serde_json::json!(1),
            },
            Step::Perform {
                target: "effect://x/b".into(),
                input: Some(serde_json::json!("${a}")),
            },
        ]))
        .unwrap();
        assert!(matches!(node, DoNode::Let { .. }));
    }

    #[test]
    fn three_independent_steps_pairwise_parallel() {
        // Limitation: greedy pairwise, so [A,B,C] → Let(Both(A,B), C), not 3-way.
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
        ]))
        .unwrap();
        match node {
            DoNode::Let { value, body, .. } => {
                assert!(matches!(*value, DoNode::Both(_, _)));
                assert!(matches!(*body, DoNode::Op(_)));
            }
            _ => panic!("expected Let wrapping Both"),
        }
    }
}
