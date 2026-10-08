#![forbid(unsafe_code)]

//! Plan document compiler.
//!
//! This crate parses YAML or JSON [`Plan`] documents and lowers them to
//! [`DoNode`](xolotl_graph::DoNode) programs for kernel execution.

use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(test)]
use xolotl_graph::DoNode;
use xolotl_types::{Path, PathRegistry};

mod compiler;
#[cfg(test)]
use compiler::json_to_value;
pub use compiler::{CompileLimits, compile, compile_with_limits};
#[cfg(test)]
use xolotl_types::Value;

/// JSON value used by Plan documents before they are lowered to
/// [`xolotl_types::Value`].
pub type JsonValue = serde_json::Value;

/// A serializable workflow document that compiles to one
/// [`DoNode`](xolotl_graph::DoNode) program.
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
    /// Acquire a value, run the body, then release on success, failure or
    /// cooperative cancellation. Release receives the acquired value.
    Bracket {
        /// Step that acquires the resource.
        acquire: Box<Step>,
        /// Steps run while the acquired resource is bound.
        body: Vec<Step>,
        /// Release step run on every cooperative exit from the body.
        release: StepRefSpec,
    },
}

/// A process-local step reference (name + optional inline arg). The executing
/// process supplies the function; compiled plans contain no process ids for steps.
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
    /// Source bytes, output nodes, or nesting exceeded the compiler admission limit.
    #[error("plan compiler capacity exceeded")]
    Capacity,
    /// A path literal failed Xolotl path parsing.
    #[error("path: {0}")]
    Path(#[from] xolotl_types::PathError),
    /// The plan did not contain any root steps.
    #[error("plan must contain at least one step")]
    Empty,
    /// A continuation-only step appeared before any current node existed.
    #[error("step {0} cannot be the first step")]
    BadFirstStep(&'static str),
    /// A local name is not bound in the current lexical scope.
    #[error("unbound local name: {0}")]
    UnboundName(String),
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

/// Parse a YAML Plan document.
pub fn parse_yaml(src: &str) -> Result<Plan, PlanError> {
    parse_yaml_with_limits(src, CompileLimits::default())
}

/// Decode YAML within a raw source-byte bound. Decoder recursion and the
/// returned caller-owned AST lifecycle are distinct from compiler admission.
pub fn parse_yaml_with_limits(src: &str, limits: CompileLimits) -> Result<Plan, PlanError> {
    if src.len() > limits.source_bytes {
        return Err(PlanError::Capacity);
    }
    yaml_serde::from_str(src).map_err(|error| PlanError::Yaml(error.to_string()))
}

/// Parse a JSON Plan document.
pub fn parse_json(src: &str) -> Result<Plan, PlanError> {
    parse_json_with_limits(src, CompileLimits::default())
}

/// Decode JSON within a raw source-byte bound. The decoder retains its own
/// recursion limit; raising compiler depth does not raise that decoder limit.
pub fn parse_json_with_limits(src: &str, limits: CompileLimits) -> Result<Plan, PlanError> {
    if src.len() > limits.source_bytes {
        return Err(PlanError::Capacity);
    }
    serde_json::from_str(src).map_err(|error| PlanError::Json(error.to_string()))
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

    fn compile_test(plan: &Plan) -> Result<DoNode, PlanError> {
        compile(plan)
    }

    #[test]
    fn compile_single_perform() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Perform {
            target: "effect://x/post".into(),
            input: Some(serde_json::json!("hello")),
        }]))?;
        match &node {
            DoNode::Op(t) => {
                ensure!(
                    t.target.path().to_string() == "effect://x/post",
                    "unexpected target: {}",
                    t.target.path()
                );
                ensure!(t.method == "invoke", "unexpected method: {}", t.method);
                ensure!(
                    t.literal_input == Some(Value::string("hello".into())),
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
        match &node {
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
        match &set {
            DoNode::Op(t) => ensure!(t.method == "write", "unexpected method: {}", t.method),
            other => bail!("expected operation node, got {other:?}"),
        }
        let app = compile_test(&plan(vec![Step::Write {
            path: "state://log".into(),
            value: serde_json::json!("e"),
            mode: WriteModeSpec::Append,
        }]))?;
        match &app {
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
            matches!(&node, DoNode::OrElse { .. }),
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
            matches!(&par, DoNode::Both(_, _)),
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
            matches!(&race, DoNode::Race(_, _)),
            "expected Race node, got {race:?}"
        );
        Ok(())
    }

    #[test]
    fn acting_compiles() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![Step::Acting {
            identity: "identity://alice".into(),
            body: vec![Step::Pure {
                value: serde_json::json!(1),
            }],
        }]))?;
        ensure!(
            matches!(&node, DoNode::Acting { .. }),
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
        match &node {
            DoNode::Op(t) => {
                ensure!(t.method == "subscribe", "unexpected method: {}", t.method);
                ensure!(
                    t.literal_input.as_ref().and_then(Value::as_map).is_some(),
                    "unexpected input: {:?}",
                    t.literal_input
                );
            }
            other => bail!("expected operation node, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn bracket_compiles_to_let_with_finally_and_resource_release() -> anyhow::Result<()> {
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
        match &node {
            DoNode::Let { body, .. } => match body.as_ref() {
                DoNode::Finally { cleanup, .. } => ensure!(
                    matches!(cleanup.as_ref(), DoNode::AndThen { d, then }
                        if matches!(d.as_ref(), DoNode::Use(name) if name == "_resource")
                            && then.name == "release"),
                    "release must receive the acquired resource"
                ),
                other => bail!("expected Finally release body, got {other:?}"),
            },
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
        match v.as_map() {
            Some(m) => {
                ensure!(
                    m.get("n").context("missing n")? == &Value::integer(7),
                    "unexpected n"
                );
                ensure!(
                    m.get("ok").context("missing ok")? == &Value::boolean(true),
                    "unexpected ok"
                );
                ensure!(
                    m.get("list").context("missing list")?.as_list().is_some(),
                    "unexpected list"
                );
            }
            other => bail!("expected map value, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn duplicate_let_name_shadows() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Let {
                name: "x".into(),
                value: serde_json::json!(1),
            },
            Step::Let {
                name: "x".into(),
                value: serde_json::json!(2),
            },
            Step::Use { name: "x".into() },
        ]))?;
        xolotl_graph::compile_do(&node)?;
        Ok(())
    }

    #[test]
    fn placeholder_strings_are_literals() -> anyhow::Result<()> {
        let node = compile_test(&plan(vec![
            Step::Let {
                name: "a".into(),
                value: serde_json::json!("${b}"),
            },
            Step::Let {
                name: "b".into(),
                value: serde_json::json!("${a}"),
            },
            Step::Use { name: "b".into() },
        ]))?;
        xolotl_graph::compile_do(&node)?;
        Ok(())
    }

    #[test]
    fn effect_steps_are_sequential() -> anyhow::Result<()> {
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
            matches!(&node, DoNode::Let { .. }),
            "effects must remain sequential, got {node:?}"
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
            matches!(&node, DoNode::Let { .. }),
            "expected Let node, got {node:?}"
        );
        Ok(())
    }

    #[test]
    fn three_effect_steps_remain_sequential() -> anyhow::Result<()> {
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
        match &node {
            DoNode::Let { value, body, .. } => {
                ensure!(
                    matches!(value.as_ref(), DoNode::Let { .. }),
                    "expected sequential prefix, got {value:?}"
                );
                ensure!(
                    matches!(body.as_ref(), DoNode::Op(_)),
                    "expected Op body, got {body:?}"
                );
            }
            other => bail!("expected sequential Let, got {other:?}"),
        }
        Ok(())
    }
}
