//! Host import operands participate in the same table as all machine values.

use super::{ValueRoot, ValueTableDecoder, ValueTableEncodeError, ValueTableEncoder, resolve};
use crate::executor::image::Import;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use xolotl_graph::{OperationTemplate, StepRef, WaitSpec, portable::Transform};
use xolotl_types::{MethodId, OutputMode, Path, ResourceName};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum ImportRecord<'a> {
    Vacant,
    Operation(OperationRecord<'a>, bool),
    Step {
        name: Cow<'a, str>,
        arg: Option<ValueRoot>,
        revision: Option<crate::LoaderRevision>,
    },
    Wait(Cow<'a, WaitSpec>),
    Scope(Cow<'a, Path>),
    Transform(TransformRecord<'a>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationRecord<'a> {
    target: Cow<'a, ResourceName>,
    method: Cow<'a, str>,
    method_id: Option<MethodId>,
    output: OutputMode,
    literal_input: Option<ValueRoot>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TransformRecord<'a> {
    Field { name: Cow<'a, str> },
    Index { index: usize },
    Add { value: i64 },
    LessThan { value: i64 },
    Equal { value: ValueRoot },
    Not,
    Length,
}

impl<'a> ImportRecord<'a> {
    pub(super) fn new(
        import: &'a Import,
        values: &mut ValueTableEncoder<'a>,
    ) -> Result<Self, ValueTableEncodeError> {
        Ok(match import {
            Import::Vacant => Self::Vacant,
            Import::Operation(operation, next) => Self::Operation(
                OperationRecord {
                    target: Cow::Borrowed(&operation.target),
                    method: Cow::Borrowed(&operation.method),
                    method_id: operation.method_id,
                    output: operation.output,
                    literal_input: operation
                        .literal_input
                        .as_ref()
                        .map(|value| values.intern(value))
                        .transpose()?,
                },
                *next,
            ),
            Import::Step(step, revision) => Self::Step {
                name: Cow::Borrowed(&step.name),
                arg: step
                    .arg
                    .as_ref()
                    .map(|value| values.intern(value))
                    .transpose()?,
                revision: *revision,
            },
            Import::Wait(wait) => Self::Wait(Cow::Borrowed(wait)),
            Import::Scope(path) => Self::Scope(Cow::Borrowed(path)),
            Import::Transform(transform) => Self::Transform(match transform {
                Transform::Field { name } => TransformRecord::Field {
                    name: Cow::Borrowed(name),
                },
                Transform::Index { index } => TransformRecord::Index { index: *index },
                Transform::Add { value } => TransformRecord::Add { value: *value },
                Transform::LessThan { value } => TransformRecord::LessThan { value: *value },
                Transform::Equal { value } => TransformRecord::Equal {
                    value: values.intern(value)?,
                },
                Transform::Not => TransformRecord::Not,
                Transform::Length => TransformRecord::Length,
            }),
        })
    }

    pub(super) fn restore(self, values: &ValueTableDecoder) -> Result<Import, &'static str> {
        Ok(match self {
            Self::Vacant => Import::Vacant,
            Self::Operation(operation, next) => Import::Operation(
                OperationTemplate {
                    target: operation.target.into_owned(),
                    method: operation.method.into_owned(),
                    method_id: operation.method_id,
                    output: operation.output,
                    literal_input: operation
                        .literal_input
                        .map(|root| resolve(values, root))
                        .transpose()?,
                },
                next,
            ),
            Self::Step {
                name,
                arg,
                revision,
            } => Import::Step(
                StepRef {
                    name: name.into_owned(),
                    arg: arg.map(|root| resolve(values, root)).transpose()?,
                },
                revision,
            ),
            Self::Wait(wait) => Import::Wait(wait.into_owned()),
            Self::Scope(path) => Import::Scope(path.into_owned()),
            Self::Transform(transform) => Import::Transform(match transform {
                TransformRecord::Field { name } => Transform::Field {
                    name: name.into_owned(),
                },
                TransformRecord::Index { index } => Transform::Index { index },
                TransformRecord::Add { value } => Transform::Add { value },
                TransformRecord::LessThan { value } => Transform::LessThan { value },
                TransformRecord::Equal { value } => Transform::Equal {
                    value: resolve(values, value)?,
                },
                TransformRecord::Not => Transform::Not,
                TransformRecord::Length => Transform::Length,
            }),
        })
    }
}
