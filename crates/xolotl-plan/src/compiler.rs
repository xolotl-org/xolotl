use super::{JsonValue, Plan, PlanError, Step, StepRefSpec};
use std::collections::{BTreeMap, BTreeSet};
use xolotl_graph::{DoNode, OperationTemplate, StepRef};
use xolotl_types::{OutputMode, Path, ResourceName, Value, default_registry};

/// Admission bounds for the borrowed Plan compiler, not host RSS limits.
/// The caller owns construction, deserialization, and destruction of its AST.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    /// Maximum compact JSON bytes of the resident Plan, including literals,
    /// escaped strings, metadata, and schema envelopes. Raw parsing also checks
    /// the input length, including whitespace, before deserializing.
    pub source_bytes: usize,
    /// Maximum output DoNode nodes, including synthetic sequence, binding,
    /// and bracket nodes. This is not the later graph compiler's image limit.
    pub instructions: usize,
    /// Maximum nested step/literal depth. Root steps have depth one; their
    /// literal roots and nested steps have depth two. Metadata has no depth.
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

/// Compile a borrowed Plan with default admission bounds. The output owns its
/// constants and names; no AST borrow escapes. Caller AST lifecycle is excluded.
pub fn compile(plan: &Plan) -> Result<DoNode, PlanError> {
    compile_with_limits(plan, CompileLimits::default())
}

/// Validate all source and output bounds before lowering or copying literals.
/// Validation, lexical lowering, and JSON conversion use explicit cursors,
/// never recursive descent or a flattened copy of the complete source tree.
/// Unbound sequence segments are balanced without reordering stages. Modifiers
/// still wrap the entire preceding segment, and named bindings retain their
/// lexical scope. Successful results still feed subsequent stages as their
/// input; failures still stop before subsequent stages.
pub fn compile_with_limits(plan: &Plan, limits: CompileLimits) -> Result<DoNode, PlanError> {
    if plan.steps.is_empty() {
        return Err(PlanError::Empty);
    }
    let reserved = validate(plan, limits)?;
    Lowering {
        scope: Vec::new(),
        reserved,
        next_temporary: 0,
    }
    .lower(&plan.steps)
}

struct Budget {
    bytes: usize,
    instructions: usize,
    depth: usize,
}

impl Budget {
    fn bytes(&mut self, amount: usize) -> Result<(), PlanError> {
        self.bytes = self.bytes.checked_sub(amount).ok_or(PlanError::Capacity)?;
        Ok(())
    }

    fn nodes(&mut self, amount: usize) -> Result<(), PlanError> {
        self.instructions = self
            .instructions
            .checked_sub(amount)
            .ok_or(PlanError::Capacity)?;
        Ok(())
    }

    fn depth(&self, depth: usize) -> Result<(), PlanError> {
        if depth > self.depth {
            return Err(PlanError::Capacity);
        }
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), PlanError> {
        self.bytes(2)?;
        for byte in value.bytes() {
            self.bytes(match byte {
                b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
                0..=31 => 6,
                _ => 1,
            })?;
        }
        Ok(())
    }

    fn optional_json(&mut self, value: &Option<JsonValue>, depth: usize) -> Result<(), PlanError> {
        match value {
            Some(value) => self.json(value, depth),
            None => self.bytes(4),
        }
    }

    fn reference(&mut self, step: &StepRefSpec, depth: usize) -> Result<(), PlanError> {
        self.bytes(r#"{"name":,"arg":}"#.len())?;
        self.string(&step.name)?;
        self.optional_json(&step.arg, depth)
    }

    fn json(&mut self, root: &JsonValue, depth: usize) -> Result<(), PlanError> {
        enum Cursor<'a> {
            Node(&'a JsonValue, usize),
            Array(std::slice::Iter<'a, JsonValue>, usize),
            Object(serde_json::map::Iter<'a>, usize),
        }
        let mut pending = vec![Cursor::Node(root, depth)];
        while let Some(cursor) = pending.pop() {
            let (value, depth) = match cursor {
                Cursor::Node(value, depth) => (value, depth),
                Cursor::Array(mut values, depth) => {
                    if let Some(value) = values.next() {
                        pending.push(Cursor::Array(values, depth));
                        pending.push(Cursor::Node(value, depth));
                    }
                    continue;
                }
                Cursor::Object(mut values, depth) => {
                    if let Some((key, value)) = values.next() {
                        self.string(key)?;
                        self.bytes(1)?;
                        pending.push(Cursor::Object(values, depth));
                        pending.push(Cursor::Node(value, depth));
                    }
                    continue;
                }
            };
            self.depth(depth)?;
            match value {
                JsonValue::Null => self.bytes(4)?,
                JsonValue::Bool(value) => self.bytes(if *value { 4 } else { 5 })?,
                JsonValue::Number(value) => self.bytes(value.to_string().len())?,
                JsonValue::String(value) => self.string(value)?,
                JsonValue::Array(values) => {
                    self.bytes(2 + values.len().saturating_sub(1))?;
                    pending.push(Cursor::Array(values.iter(), depth.saturating_add(1)));
                }
                JsonValue::Object(values) => {
                    self.bytes(2 + values.len().saturating_sub(1))?;
                    pending.push(Cursor::Object(values.iter(), depth.saturating_add(1)));
                }
            }
        }
        Ok(())
    }
}

fn validate(plan: &Plan, limits: CompileLimits) -> Result<BTreeSet<&str>, PlanError> {
    let mut budget = Budget {
        bytes: limits.source_bytes,
        instructions: limits.instructions,
        depth: limits.expression_depth,
    };
    budget.bytes(r#"{"id":,"version":,"description":,"steps":}"#.len())?;
    budget.string(&plan.id)?;
    budget.bytes(plan.version.to_string().len())?;
    match &plan.description {
        Some(description) => budget.string(description)?,
        None => budget.bytes(4)?,
    }
    enum Cursor<'a> {
        Step(&'a Step, usize),
        Sequence(std::slice::Iter<'a, Step>, usize),
    }
    fn sequence<'a>(
        steps: &'a [Step],
        depth: usize,
        budget: &mut Budget,
        pending: &mut Vec<Cursor<'a>>,
    ) -> Result<(), PlanError> {
        budget.bytes(2 + steps.len().saturating_sub(1))?;
        if steps.is_empty() {
            return Err(PlanError::Empty);
        }
        let stages = steps
            .iter()
            .filter(|step| !matches!(step, Step::Then { .. } | Step::OnFail { .. }))
            .count();
        budget.nodes(stages.saturating_sub(1))?;
        pending.push(Cursor::Sequence(steps.iter(), depth));
        Ok(())
    }
    let mut pending = Vec::new();
    sequence(&plan.steps, 1, &mut budget, &mut pending)?;
    let mut reserved = BTreeSet::new();
    let registry = default_registry();
    while let Some(cursor) = pending.pop() {
        let (step, depth) = match cursor {
            Cursor::Step(step, depth) => (step, depth),
            Cursor::Sequence(mut steps, depth) => {
                if let Some(step) = steps.next() {
                    pending.push(Cursor::Sequence(steps, depth));
                    pending.push(Cursor::Step(step, depth));
                }
                continue;
            }
        };
        budget.depth(depth)?;
        budget.nodes(if matches!(step, Step::Bracket { .. }) {
            4
        } else {
            1
        })?;
        let child_depth = depth.saturating_add(1);
        match step {
            Step::Perform { target, input } => {
                budget.bytes(r#"{"kind":"perform","target":,"input":}"#.len())?;
                budget.string(target)?;
                budget.optional_json(input, child_depth)?;
            }
            Step::Read { path, r#as } => {
                budget.bytes(r#"{"kind":"read","path":,"as":}"#.len())?;
                budget.string(path)?;
                budget.string(r#as)?;
                reserved.insert(r#as.as_str());
            }
            Step::Subscribe { path, step } => {
                budget.bytes(r#"{"kind":"subscribe","path":,"step":}"#.len())?;
                budget.string(path)?;
                budget.reference(step, child_depth)?;
            }
            Step::Write { path, value, mode } => {
                budget.bytes(r#"{"kind":"write","path":,"value":,"mode":}"#.len())?;
                budget.string(path)?;
                budget.json(value, child_depth)?;
                budget.string(match mode {
                    super::WriteModeSpec::Set => "set",
                    super::WriteModeSpec::Append => "append",
                })?;
            }
            Step::Then { name, arg } | Step::OnFail { name, arg } => {
                budget.bytes(if matches!(step, Step::Then { .. }) {
                    r#"{"kind":"then","name":,"arg":}"#.len()
                } else {
                    r#"{"kind":"on_fail","name":,"arg":}"#.len()
                })?;
                budget.string(name)?;
                budget.optional_json(arg, child_depth)?;
            }
            Step::Parallel { left, right } | Step::Race { left, right } => {
                budget.bytes(if matches!(step, Step::Parallel { .. }) {
                    r#"{"kind":"parallel","left":,"right":}"#.len()
                } else {
                    r#"{"kind":"race","left":,"right":}"#.len()
                })?;
                sequence(right, child_depth, &mut budget, &mut pending)?;
                sequence(left, child_depth, &mut budget, &mut pending)?;
            }
            Step::Let { name, value } => {
                budget.bytes(r#"{"kind":"let","name":,"value":}"#.len())?;
                budget.string(name)?;
                budget.json(value, child_depth)?;
                reserved.insert(name.as_str());
            }
            Step::Use { name } => {
                budget.bytes(r#"{"kind":"use","name":}"#.len())?;
                budget.string(name)?;
                reserved.insert(name.as_str());
            }
            Step::Pure { value } => {
                budget.bytes(r#"{"kind":"pure","value":}"#.len())?;
                budget.json(value, child_depth)?;
            }
            Step::Acting { identity, body } => {
                budget.bytes(r#"{"kind":"acting","identity":,"body":}"#.len())?;
                budget.string(identity)?;
                super::validate_identity_literal("acting identity", identity)?;
                sequence(body, child_depth, &mut budget, &mut pending)?;
            }
            Step::Bracket {
                acquire,
                body,
                release,
            } => {
                budget.bytes(r#"{"kind":"bracket","acquire":,"body":,"release":}"#.len())?;
                budget.reference(release, child_depth)?;
                sequence(body, child_depth, &mut budget, &mut pending)?;
                pending.push(Cursor::Step(acquire, child_depth));
            }
        }
        super::validate_step_target(step, &registry)?;
    }
    Ok(reserved)
}

struct Sequence<'a> {
    steps: &'a [Step],
    index: usize,
    scope_start: usize,
    segment: Vec<(usize, DoNode)>,
    bindings: Vec<(&'a str, DoNode)>,
    waiting: bool,
}

impl<'a> Sequence<'a> {
    fn new(steps: &'a [Step], scope_start: usize) -> Self {
        Self {
            steps,
            index: 0,
            scope_start,
            segment: Vec::new(),
            bindings: Vec::new(),
            waiting: false,
        }
    }
}

enum Work<'a> {
    Sequence(Sequence<'a>),
    Step(&'a Step),
    Left {
        right: &'a [Step],
        race: bool,
    },
    Right {
        left: DoNode,
        race: bool,
    },
    Acting(&'a str),
    Acquire {
        body: &'a [Step],
        release: &'a StepRefSpec,
    },
    Bracket {
        acquire: DoNode,
        release: &'a StepRefSpec,
        scope_start: usize,
    },
}

struct Lowering<'a> {
    scope: Vec<&'a str>,
    reserved: BTreeSet<&'a str>,
    next_temporary: usize,
}

impl<'a> Lowering<'a> {
    fn append(&mut self, sequence: &mut Sequence<'a>, next: DoNode) {
        let mut node = next;
        let mut weight = 1;
        while sequence
            .segment
            .last()
            .is_some_and(|(last, _)| *last == weight)
        {
            if let Some((_, prefix)) = sequence.segment.pop() {
                node = self.sequence(Some(prefix), node);
                weight *= 2;
            }
        }
        sequence.segment.push((weight, node));
    }

    fn finish_segment(&mut self, sequence: &mut Sequence<'a>) -> Result<DoNode, PlanError> {
        let (_, mut node) = sequence.segment.pop().ok_or(PlanError::Empty)?;
        while let Some((_, prefix)) = sequence.segment.pop() {
            node = self.sequence(Some(prefix), node);
        }
        Ok(node)
    }

    fn sequence(&mut self, prefix: Option<DoNode>, next: DoNode) -> DoNode {
        match prefix {
            Some(prefix) => loop {
                let name = format!("_plan_sequence_{}", self.next_temporary);
                self.next_temporary += 1;
                if !self.reserved.contains(name.as_str()) {
                    break DoNode::r#let(name, prefix, next);
                }
            },
            None => next,
        }
    }

    fn lower(&mut self, steps: &'a [Step]) -> Result<DoNode, PlanError> {
        let mut work = vec![Work::Sequence(Sequence::new(steps, 0))];
        let mut output = None;
        while let Some(item) = work.pop() {
            match item {
                Work::Sequence(mut sequence) => {
                    let steps = sequence.steps;
                    if sequence.waiting {
                        let step = &steps[sequence.index];
                        self.append(&mut sequence, output.take().ok_or(PlanError::Empty)?);
                        sequence.index += 1;
                        if let Some(name) = match step {
                            Step::Let { name, .. } => Some(name.as_str()),
                            Step::Read { r#as, .. } => Some(r#as.as_str()),
                            _ => None,
                        } {
                            while let Some(modifier) = steps.get(sequence.index) {
                                if !matches!(modifier, Step::Then { .. } | Step::OnFail { .. }) {
                                    break;
                                }
                                let current = self.finish_segment(&mut sequence)?;
                                self.append(&mut sequence, modify(Some(current), modifier)?);
                                sequence.index += 1;
                            }
                            if sequence.index < steps.len() {
                                let value = self.finish_segment(&mut sequence)?;
                                sequence.bindings.push((name, value));
                                self.scope.push(name);
                            }
                        }
                        sequence.waiting = false;
                    }
                    match steps.get(sequence.index) {
                        Some(step @ (Step::Then { .. } | Step::OnFail { .. })) => {
                            let current = if sequence.segment.is_empty() {
                                None
                            } else {
                                Some(self.finish_segment(&mut sequence)?)
                            };
                            self.append(&mut sequence, modify(current, step)?);
                            sequence.index += 1;
                            work.push(Work::Sequence(sequence));
                        }
                        Some(step) => {
                            sequence.waiting = true;
                            work.push(Work::Sequence(sequence));
                            work.push(Work::Step(step));
                        }
                        None => {
                            self.scope.truncate(sequence.scope_start);
                            let mut node = self.finish_segment(&mut sequence)?;
                            for (name, value) in sequence.bindings.into_iter().rev() {
                                node = DoNode::r#let(name, value, node);
                            }
                            output = Some(node);
                        }
                    }
                }
                Work::Step(step) => match step {
                    Step::Parallel { left, right } | Step::Race { left, right } => {
                        work.push(Work::Left {
                            right,
                            race: matches!(step, Step::Race { .. }),
                        });
                        work.push(Work::Sequence(Sequence::new(left, self.scope.len())));
                    }
                    Step::Acting { identity, body } => {
                        work.push(Work::Acting(identity));
                        work.push(Work::Sequence(Sequence::new(body, self.scope.len())));
                    }
                    Step::Bracket {
                        acquire,
                        body,
                        release,
                    } => {
                        work.push(Work::Acquire { body, release });
                        work.push(Work::Step(acquire));
                    }
                    _ => output = Some(self.leaf(step)?),
                },
                Work::Left { right, race } => {
                    work.push(Work::Right {
                        left: output.take().ok_or(PlanError::Empty)?,
                        race,
                    });
                    work.push(Work::Sequence(Sequence::new(right, self.scope.len())));
                }
                Work::Right { left, race } => {
                    let right = output.take().ok_or(PlanError::Empty)?;
                    output = Some(if race {
                        DoNode::race(left, right)
                    } else {
                        DoNode::both(left, right)
                    });
                }
                Work::Acting(identity) => {
                    output = Some(DoNode::acting(
                        Path::parse(identity)?,
                        output.take().ok_or(PlanError::Empty)?,
                    ));
                }
                Work::Acquire { body, release } => {
                    let scope_start = self.scope.len();
                    self.scope.push("_resource");
                    work.push(Work::Bracket {
                        acquire: output.take().ok_or(PlanError::Empty)?,
                        release,
                        scope_start,
                    });
                    work.push(Work::Sequence(Sequence::new(body, self.scope.len())));
                }
                Work::Bracket {
                    acquire,
                    release,
                    scope_start,
                } => {
                    self.scope.truncate(scope_start);
                    output = Some(DoNode::r#let(
                        "_resource",
                        acquire,
                        output.take().ok_or(PlanError::Empty)?.finally(
                            DoNode::use_("_resource")
                                .and_then(step_ref(&release.name, &release.arg)),
                        ),
                    ));
                }
            }
        }
        output.ok_or(PlanError::Empty)
    }

    fn leaf(&self, step: &Step) -> Result<DoNode, PlanError> {
        Ok(match step {
            Step::Perform { target, input } => {
                op(target, "invoke", input.as_ref().map(json_to_value))?
            }
            Step::Read { path, .. } => op(path, "read", None)?,
            Step::Subscribe { path, step } => {
                let mut input = BTreeMap::new();
                input.insert("step".into(), Value::string(step.name.clone()));
                if let Some(arg) = &step.arg {
                    input.insert("arg".into(), json_to_value(arg));
                }
                op(path, "subscribe", Some(Value::map(input)))?
            }
            Step::Write { path, value, mode } => {
                op(path, mode.method(), Some(json_to_value(value)))?
            }
            Step::Let { value, .. } | Step::Pure { value } => DoNode::pure(json_to_value(value)),
            Step::Use { name } => {
                if !self.scope.contains(&name.as_str()) {
                    return Err(PlanError::UnboundName(name.clone()));
                }
                DoNode::use_(name.clone())
            }
            Step::Then { .. } => return Err(PlanError::BadFirstStep("then")),
            Step::OnFail { .. } => return Err(PlanError::BadFirstStep("on_fail")),
            _ => return Err(PlanError::Empty),
        })
    }
}

fn modify(current: Option<DoNode>, step: &Step) -> Result<DoNode, PlanError> {
    match step {
        Step::Then { name, arg } => Ok(current
            .ok_or(PlanError::BadFirstStep("then"))?
            .and_then(step_ref(name, arg))),
        Step::OnFail { name, arg } => Ok(current
            .ok_or(PlanError::BadFirstStep("on_fail"))?
            .or_else(step_ref(name, arg))),
        _ => Err(PlanError::Empty),
    }
}

fn step_ref(name: &str, arg: &Option<JsonValue>) -> StepRef {
    let reference = StepRef::new(name);
    match arg {
        Some(arg) => reference.with_arg(json_to_value(arg)),
        None => reference,
    }
}

fn op(path: &str, method: &str, input: Option<Value>) -> Result<DoNode, PlanError> {
    Ok(DoNode::Op(OperationTemplate {
        target: ResourceName::new(Path::parse(path)?),
        method: method.to_string(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: input,
    }))
}

pub(super) fn json_to_value(root: &JsonValue) -> Value {
    enum Work<'a> {
        Node(&'a JsonValue),
        Array {
            remaining: std::slice::Iter<'a, JsonValue>,
            values: Vec<Value>,
        },
        Object {
            remaining: serde_json::map::Iter<'a>,
            values: BTreeMap<String, Value>,
            key: &'a str,
        },
    }
    let mut work = vec![Work::Node(root)];
    let mut output = Value::null();
    while let Some(item) = work.pop() {
        match item {
            Work::Node(value) => match value {
                JsonValue::Null => output = Value::null(),
                JsonValue::Bool(value) => output = Value::boolean(*value),
                JsonValue::Number(value) => {
                    output = if let Some(value) = value.as_i64() {
                        Value::integer(value)
                    } else if let Some(value) = value.as_f64() {
                        Value::float(xolotl_types::FloatBits(value))
                    } else {
                        Value::null()
                    }
                }
                JsonValue::String(value) => output = Value::string(value.clone()),
                JsonValue::Array(values) => {
                    let mut remaining = values.iter();
                    if let Some(value) = remaining.next() {
                        work.push(Work::Array {
                            remaining,
                            values: Vec::with_capacity(values.len()),
                        });
                        work.push(Work::Node(value));
                    } else {
                        output = Value::list(Vec::new());
                    }
                }
                JsonValue::Object(values) => {
                    let mut remaining = values.iter();
                    if let Some((key, value)) = remaining.next() {
                        work.push(Work::Object {
                            remaining,
                            values: BTreeMap::new(),
                            key,
                        });
                        work.push(Work::Node(value));
                    } else {
                        output = Value::map(BTreeMap::new());
                    }
                }
            },
            Work::Array {
                mut remaining,
                mut values,
            } => {
                values.push(output);
                if let Some(value) = remaining.next() {
                    work.push(Work::Array { remaining, values });
                    work.push(Work::Node(value));
                    output = Value::null();
                } else {
                    output = Value::list(values);
                }
            }
            Work::Object {
                mut remaining,
                mut values,
                key,
            } => {
                values.insert(key.to_string(), output);
                if let Some((key, value)) = remaining.next() {
                    work.push(Work::Object {
                        remaining,
                        values,
                        key,
                    });
                    work.push(Work::Node(value));
                    output = Value::null();
                } else {
                    output = Value::map(values);
                }
            }
        }
    }
    output
}
