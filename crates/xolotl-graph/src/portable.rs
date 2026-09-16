//! Portable programs: code and JSON share one compiler and instruction image.

use crate::{OperationTemplate, StepRef, WaitSpec};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use xolotl_core::{IMAGE_VERSION, Node, NodeKind, ProgramImage};
use xolotl_types::{Failure, Path, Value};

/// Portable source language version, independent of the core instruction format.
pub const SOURCE_VERSION: u32 = 1;

/// Admission limits for one resident source module, not a whole workflow.
/// Hosts may raise these for larger modules; instruction addresses still use `u32`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    /// Maximum bytes accepted by [`Program::from_json_with_limits`].
    pub source_bytes: usize,
    /// Maximum resident instructions in the compiled module.
    pub instructions: usize,
    /// Maximum nesting of the Rust expression tree during lowering.
    /// The JSON parser independently enforces its decode recursion limit.
    pub expression_depth: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            source_bytes: 1024 * 1024,
            instructions: 65_536,
            expression_depth: 128,
        }
    }
}

/// Versioned source document. Functions are lexical, not process-local Rust code.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// Source language version, currently one.
    pub version: u32,
    /// Entry expression evaluated with the caller's input.
    pub body: Expression,
    /// Named subprograms, sharing input and output conventions with the entry.
    #[serde(default)]
    pub functions: BTreeMap<String, Expression>,
    /// Require a host with persistent execution barriers.
    #[serde(default)]
    pub durable: bool,
}

impl Program {
    /// Construct a volatile program with no named functions.
    pub fn new(body: Expression) -> Self {
        Self {
            version: SOURCE_VERSION,
            body,
            functions: BTreeMap::new(),
            durable: false,
        }
    }

    /// Decode a bounded source document through the same serde representation as Rust builders.
    pub fn from_json(source: &[u8]) -> Result<Self, CompileError> {
        Self::from_json_with_limits(source, CompileLimits::default())
    }

    /// Decode a module using explicit source admission, without dispatching effects.
    pub fn from_json_with_limits(
        source: &[u8],
        limits: CompileLimits,
    ) -> Result<Self, CompileError> {
        if source.len() > limits.source_bytes {
            return Err(CompileError::Capacity);
        }
        serde_json::from_slice(source).map_err(|error| CompileError::Encoding(error.to_string()))
    }

    /// Resolve lexical slots and functions into an immutable instruction image.
    pub fn compile(&self) -> Result<CompiledProgram, CompileError> {
        self.compile_with_limits(CompileLimits::default())
    }

    /// Compile using explicit resident-module limits. Limits are not part of
    /// program identity: admitted identical sources produce identical images.
    pub fn compile_with_limits(
        &self,
        limits: CompileLimits,
    ) -> Result<CompiledProgram, CompileError> {
        if self.version != SOURCE_VERSION {
            return Err(CompileError::Version(self.version));
        }
        let mut compiler = Compiler {
            limits,
            nodes: Vec::new(),
            imports: Vec::new(),
            bindings: 0,
            live_bindings: 0,
            names: BTreeMap::new(),
            functions: BTreeMap::new(),
            calls: Vec::new(),
        };
        let entry = compiler.lower(&self.body, 0)?;
        for (name, body) in &self.functions {
            compiler.names.clear();
            let address = compiler.lower(body, 0)?;
            compiler.functions.insert(name.clone(), address);
        }
        for (node, name) in &compiler.calls {
            let entry = *compiler
                .functions
                .get(name)
                .ok_or_else(|| CompileError::Function(name.clone()))?;
            compiler.nodes[*node as usize].kind = NodeKind::Call(entry);
        }
        let hash = crate::fingerprint::image(
            &compiler.nodes,
            &compiler.imports,
            entry,
            compiler.bindings,
            self.durable,
        )
        .map_err(|error| CompileError::Encoding(error.to_string()))?;
        Ok(CompiledProgram {
            nodes: compiler.nodes,
            imports: compiler.imports,
            entry,
            bindings: compiler.bindings,
            hash,
            durable: self.durable,
        })
    }
}

/// Minimal portable source algebra. Higher-level agent patterns compose these.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expression {
    /// A JSON constant; integers must fit the signed 64-bit value representation.
    Literal {
        /// Structurally converted JSON, without untagged value inference.
        value: serde_json::Value,
    },
    /// A typed constant, including binary and media values and exact float bits.
    Constant {
        /// Losslessly encoded host value.
        #[serde(with = "xolotl_types::tagged_value")]
        value: Value,
    },
    /// Return the incoming value unchanged.
    Input,
    /// Read a lexical binding.
    Use {
        /// Name defined by an enclosing `Let`.
        name: String,
    },
    /// Bind a value for one lexical body, restoring shadowed bindings on exit.
    Let {
        /// Local binding name.
        name: String,
        /// Expression producing the bound value.
        value: Box<Expression>,
        /// Expression executed in the binding's scope.
        body: Box<Expression>,
    },
    /// Pipe each successful result into the next expression.
    Sequence {
        /// Ordered stages; an empty sequence returns its input.
        steps: Vec<Expression>,
    },
    /// Invoke a host resource through the existing capability data plane.
    Invoke {
        /// Operation descriptor; literal inputs use explicit value tags in JSON.
        operation: OperationTemplate,
    },
    /// Apply an effect-free built-in value transformation.
    Transform {
        /// Transformation receiving the current value.
        operation: Transform,
    },
    /// Evaluate a boolean condition and preserve original input for the selected branch.
    If {
        /// Boolean-producing expression.
        condition: Box<Expression>,
        /// Branch selected by true.
        yes: Box<Expression>,
        /// Branch selected by false.
        no: Box<Expression>,
    },
    /// Iterate over a loop-carried value with an explicit execution bound.
    While {
        /// Boolean test evaluated before every body execution.
        condition: Box<Expression>,
        /// Expression producing the next loop value.
        body: Box<Expression>,
        /// Maximum number of body executions before failure.
        max_iterations: u64,
    },
    /// Evaluate both branches concurrently and pair results in source order.
    Parallel {
        /// First branch.
        left: Box<Expression>,
        /// Second branch.
        right: Box<Expression>,
    },
    /// Return the first branch result after cancelling and cleaning up the other branch.
    Race {
        /// First competitor.
        left: Box<Expression>,
        /// Second competitor.
        right: Box<Expression>,
    },
    /// Handle ordinary failures; cooperative cancellation bypasses the handler.
    Catch {
        /// Guarded expression.
        body: Box<Expression>,
        /// Expression receiving the failure text.
        recover: Box<Expression>,
    },
    /// Run cleanup after success, failure or cooperative cancellation.
    Finally {
        /// Expression whose original result is preserved.
        body: Box<Expression>,
        /// Cleanup receives the guarded expression's original input.
        cleanup: Box<Expression>,
    },
    /// Enter a named subprogram using bounded continuation storage.
    Call {
        /// Name in the program's function table.
        function: String,
    },
    /// Load a host-bound continuation into this execution on demand.
    /// The host resolves the name alongside native Step bindings.
    Module {
        /// Loader name and optional constant argument.
        module: StepRef,
    },
    /// Suspend on a host signal or absolute deadline.
    Wait {
        /// Host wait specification.
        wait: WaitSpec,
    },
    /// Authorize a scoped identity change before entering the body.
    Acting {
        /// Requested acting identity.
        identity: Path,
        /// Expression run under the authorized identity.
        body: Box<Expression>,
    },
    /// Raise an ordinary program failure.
    Fail {
        /// Detail passed to the nearest handler or caller.
        message: String,
    },
}

impl Expression {
    /// Construct a plain JSON constant.
    pub fn literal(value: impl Into<serde_json::Value>) -> Self {
        Self::Literal {
            value: value.into(),
        }
    }
    /// Append a stage, keeping fluent sequences flat in the source representation.
    pub fn then(self, next: Self) -> Self {
        match self {
            Self::Sequence { mut steps } => {
                steps.push(next);
                Self::Sequence { steps }
            }
            first => Self::Sequence {
                steps: vec![first, next],
            },
        }
    }
    /// Pair this expression's result with another concurrent branch.
    pub fn both(self, right: Self) -> Self {
        Self::Parallel {
            left: Box::new(self),
            right: Box::new(right),
        }
    }
    /// Race this expression against another branch with structured cancellation.
    pub fn race(self, right: Self) -> Self {
        Self::Race {
            left: Box::new(self),
            right: Box::new(right),
        }
    }
    /// Attach cleanup to every cooperative exit of this expression.
    pub fn finally(self, cleanup: Self) -> Self {
        Self::Finally {
            body: Box::new(self),
            cleanup: Box::new(cleanup),
        }
    }
}

/// Deterministic transforms, with the same behavior for every source frontend.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transform {
    /// Extract a map field, failing if absent.
    Field {
        /// Field to extract.
        name: String,
    },
    /// Extract a list element, failing if out of bounds.
    Index {
        /// Zero-based element index.
        index: usize,
    },
    /// Add a signed integer, rejecting overflow.
    Add {
        /// Constant operand.
        value: i64,
    },
    /// Compare a signed integer against a constant.
    LessThan {
        /// Exclusive upper bound.
        value: i64,
    },
    /// Test exact semantic equality with a typed constant.
    Equal {
        /// Constant operand.
        #[serde(with = "xolotl_types::tagged_value")]
        value: Value,
    },
    /// Negate a boolean value.
    Not,
    /// Count map/list entries or Unicode scalar values in a string.
    Length,
}

impl Transform {
    /// Transform values without performing any external effects.
    pub fn apply(&self, input: Value) -> Result<Value, Failure> {
        let invalid = || Failure::InvalidInput {
            reason: format!("invalid operand for {self:?}"),
        };
        match (self, input.view()) {
            (Self::Field { name }, xolotl_types::ValueView::Map(map)) => {
                map.get(name).cloned().ok_or_else(invalid)
            }
            (Self::Index { index }, xolotl_types::ValueView::List(list)) => {
                list.get(*index).cloned().ok_or_else(invalid)
            }
            (Self::Add { value }, xolotl_types::ValueView::Int(input)) => input
                .checked_add(*value)
                .map(Value::integer)
                .ok_or_else(invalid),
            (Self::LessThan { value }, xolotl_types::ValueView::Int(input)) => {
                Ok(Value::boolean(input < *value))
            }
            (Self::Equal { value }, _) => Ok(Value::boolean(&input == value)),
            (Self::Not, xolotl_types::ValueView::Bool(input)) => Ok(Value::boolean(!input)),
            (Self::Length, xolotl_types::ValueView::List(input)) => i64::try_from(input.len())
                .map(Value::integer)
                .map_err(|_error| invalid()),
            (Self::Length, xolotl_types::ValueView::Map(input)) => i64::try_from(input.len())
                .map(Value::integer)
                .map_err(|_error| invalid()),
            (Self::Length, xolotl_types::ValueView::Str(input)) => {
                i64::try_from(input.chars().count())
                    .map(Value::integer)
                    .map_err(|_error| invalid())
            }
            _ => Err(invalid()),
        }
    }
}

/// Imports are explicit and can be inspected before executing untrusted plans.
#[derive(Clone, Debug)]
pub enum Import {
    /// Capability-authorized resource operation.
    Operation(OperationTemplate),
    /// Effect-free value transformation.
    Transform(Transform),
    /// Host event or deadline wait.
    Wait(WaitSpec),
    /// Scoped acting-identity authorization.
    Scope(Path),
    /// A continuation resolved by the host's composed module namespace.
    Module(StepRef),
}

/// Reusable program image, shared across executions with separate mutable storage.
#[derive(Clone, Debug)]
pub struct CompiledProgram<V = Value, E = Failure> {
    nodes: Vec<Node<V, E>>,
    imports: Vec<Import>,
    entry: u32,
    bindings: usize,
    hash: [u8; 32],
    durable: bool,
}

impl CompiledProgram<Value> {
    /// Move authored constants into the shared runtime provenance model.
    /// Payload buffers, imports, positions and artifact identity are preserved.
    /// The returned image can be executed with `kernel::RuntimeValues` on any host.
    pub fn with_provenance(
        self,
    ) -> CompiledProgram<xolotl_types::TaintedValue, xolotl_types::TaintedFailure> {
        CompiledProgram {
            nodes: self
                .nodes
                .into_iter()
                .map(|node| {
                    node.map_owned(
                        |value| {
                            xolotl_types::TaintedValue::new(value, xolotl_types::TaintSet::author())
                        },
                        xolotl_types::TaintedFailure::pristine,
                    )
                })
                .collect(),
            imports: self.imports,
            entry: self.entry,
            bindings: self.bindings,
            hash: self.hash,
            durable: self.durable,
        }
    }
}

impl<V, E> CompiledProgram<V, E> {
    /// Inspect the explicit host imports without mutating the compiled artifact.
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Stable instruction and import identity used to bind recovery artifacts.
    /// Value allocation layout and source-only lexical names do not affect it.
    pub fn id(&self) -> [u8; 32] {
        self.hash
    }

    /// Borrow the immutable instruction image in the compiler's value representation.
    pub fn image(&self) -> ProgramImage<'_, V, E> {
        ProgramImage {
            version: IMAGE_VERSION,
            id: self.hash,
            nodes: &self.nodes,
            entry: self.entry,
            bindings: self.bindings,
            imports: self.imports.len(),
            durable: self.durable,
        }
    }

    /// Transfer instruction and import ownership to a host image adapter.
    /// Read the image's metadata before consuming this artifact.
    pub fn into_parts(self) -> (Vec<Node<V, E>>, Vec<Import>) {
        (self.nodes, self.imports)
    }
}

/// Source validation or compilation failure, before any host effects are dispatched.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// Unsupported source version.
    #[error("unsupported portable program version {0}")]
    Version(u32),
    /// A lexical name is not in scope.
    #[error("unbound variable {0:?}")]
    Variable(String),
    /// A named subprogram does not exist.
    #[error("unknown function {0:?}")]
    Function(String),
    /// Source or instruction size exceeds compiler admission limits.
    #[error("program exceeds compiler limits")]
    Capacity,
    /// Invalid source serialization or value representation.
    #[error("program encoding failed: {0}")]
    Encoding(String),
}

struct Compiler {
    limits: CompileLimits,
    nodes: Vec<Node<Value, Failure>>,
    imports: Vec<Import>,
    bindings: usize,
    live_bindings: usize,
    names: BTreeMap<String, u32>,
    functions: BTreeMap<String, u32>,
    calls: Vec<(u32, String)>,
}

impl Compiler {
    fn push(&mut self, kind: NodeKind<Value, Failure>) -> Result<u32, CompileError> {
        if self.nodes.len() >= self.limits.instructions {
            return Err(CompileError::Capacity);
        }
        let index = u32::try_from(self.nodes.len()).map_err(|_error| CompileError::Capacity)?;
        self.nodes.push(Node::new(kind, u64::from(index)));
        Ok(index)
    }
    fn import(&mut self, import: Import) -> Result<u32, CompileError> {
        let index = u32::try_from(self.imports.len()).map_err(|_error| CompileError::Capacity)?;
        self.imports.push(import);
        Ok(index)
    }
    fn lower(&mut self, expression: &Expression, depth: usize) -> Result<u32, CompileError> {
        if depth > self.limits.expression_depth {
            return Err(CompileError::Capacity);
        }
        let depth = depth + 1;
        let kind = match expression {
            Expression::Literal { value } => NodeKind::Literal(
                json_value(value).map_err(|error| CompileError::Encoding(error.to_string()))?,
            ),
            Expression::Constant { value } => NodeKind::Literal(value.clone()),
            Expression::Input => NodeKind::Input,
            Expression::Use { name } => NodeKind::Load(
                *self
                    .names
                    .get(name)
                    .ok_or_else(|| CompileError::Variable(name.clone()))?,
            ),
            Expression::Invoke { operation } => {
                NodeKind::Request(self.import(Import::Operation(operation.clone()))?)
            }
            Expression::Transform { operation } => {
                NodeKind::Request(self.import(Import::Transform(operation.clone()))?)
            }
            Expression::Wait { wait } => {
                NodeKind::Request(self.import(Import::Wait(wait.clone()))?)
            }
            Expression::Fail { message } => NodeKind::Fail(Failure::policy("program", message)),
            Expression::Call { function } => {
                let index = self.push(NodeKind::Input)?;
                self.calls.push((index, function.clone()));
                return Ok(index);
            }
            Expression::Module { module } => {
                NodeKind::Request(self.import(Import::Module(module.clone()))?)
            }
            Expression::Let { name, value, body } => {
                let value = self.lower(value, depth)?;
                let slot =
                    u32::try_from(self.live_bindings).map_err(|_error| CompileError::Capacity)?;
                self.live_bindings += 1;
                self.bindings = self.bindings.max(self.live_bindings);
                let previous = self.names.insert(name.clone(), slot);
                let body = self.lower(body, depth)?;
                self.live_bindings -= 1;
                match previous {
                    Some(old) => {
                        self.names.insert(name.clone(), old);
                    }
                    None => {
                        self.names.remove(name);
                    }
                }
                NodeKind::Let { slot, value, body }
            }
            Expression::Sequence { steps } => {
                let mut result = None;
                // Each child's lexical environment is restored by lower().
                for step in steps.iter().rev() {
                    let first = self.lower(step, depth)?;
                    if let Some(then) = result {
                        let mut last = first;
                        while let Some(next) = self.nodes[last as usize].next {
                            last = next;
                        }
                        self.nodes[last as usize].next = Some(then);
                    }
                    result = Some(first);
                }
                return match result {
                    Some(entry) => Ok(entry),
                    None => self.push(NodeKind::Input),
                };
            }
            Expression::If { condition, yes, no } => {
                let first = self.lower(condition, depth)?;
                let yes = self.lower(yes, depth)?;
                let no = self.lower(no, depth)?;
                NodeKind::Branch {
                    condition: first,
                    yes,
                    no,
                }
            }
            Expression::While {
                condition,
                body,
                max_iterations,
            } => NodeKind::While {
                condition: self.lower(condition, depth)?,
                body: self.lower(body, depth)?,
                max: *max_iterations,
            },
            Expression::Parallel { left, right } | Expression::Race { left, right } => {
                NodeKind::Fork {
                    left: self.lower(left, depth)?,
                    right: self.lower(right, depth)?,
                    join: if matches!(expression, Expression::Parallel { .. }) {
                        xolotl_core::Join::All
                    } else {
                        xolotl_core::Join::Race
                    },
                }
            }
            Expression::Catch { body, recover } => NodeKind::Catch {
                body: self.lower(body, depth)?,
                recover: self.lower(recover, depth)?,
            },
            Expression::Finally { body, cleanup } => NodeKind::Finally {
                body: self.lower(body, depth)?,
                cleanup: self.lower(cleanup, depth)?,
            },
            Expression::Acting { identity, body } => NodeKind::Scope {
                import: self.import(Import::Scope(identity.clone()))?,
                body: self.lower(body, depth)?,
            },
        };
        self.push(kind)
    }
}

fn json_value(value: &serde_json::Value) -> Result<Value, Failure> {
    Ok(match value {
        serde_json::Value::Null => Value::null(),
        serde_json::Value::Bool(value) => Value::boolean(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Value::integer(value)
            } else if value.is_f64() {
                Value::float(xolotl_types::FloatBits(value.as_f64().ok_or_else(
                    || Failure::InvalidInput {
                        reason: "invalid float".into(),
                    },
                )?))
            } else {
                return Err(Failure::InvalidInput {
                    reason: "integer exceeds signed 64-bit range".into(),
                });
            }
        }
        serde_json::Value::String(value) => Value::string(value.clone()),
        serde_json::Value::Array(values) => {
            Value::list(values.iter().map(json_value).collect::<Result<_, _>>()?)
        }
        serde_json::Value::Object(values) => Value::map(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), json_value(value)?)))
                .collect::<Result<_, Failure>>()?,
        ),
    })
}

#[cfg(test)]
mod tests;
