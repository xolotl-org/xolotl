//! Lossless Console representation of kernel process-tree limits.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use xolotl_types::{BudgetSpec, Value};

#[derive(Serialize)]
struct Output {
    max_micro_usd: Option<String>,
    max_inflight_ops: Option<u32>,
    max_inference_tokens: Option<String>,
}

impl From<&BudgetSpec> for Output {
    fn from(budget: &BudgetSpec) -> Self {
        Self {
            max_micro_usd: budget.max_micro_usd.map(|value| value.to_string()),
            max_inflight_ops: budget.max_inflight_ops,
            max_inference_tokens: budget.max_inference_tokens.map(|value| value.to_string()),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Unsigned {
    Integer(u64),
    Decimal(String),
}

impl Unsigned {
    fn number<E: serde::de::Error>(self) -> Result<u64, E> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::Decimal(value)
                if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                value.parse().map_err(E::custom)
            }
            Self::Decimal(_) => Err(E::custom("expected an unsigned decimal string")),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    max_micro_usd: Option<Unsigned>,
    max_inflight_ops: Option<u32>,
    max_inference_tokens: Option<Unsigned>,
}

pub(crate) fn serialize<S: Serializer>(
    budget: &BudgetSpec,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Output::from(budget).serialize(serializer)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BudgetSpec, D::Error> {
    let input = Input::deserialize(deserializer)?;
    Ok(BudgetSpec {
        max_micro_usd: input.max_micro_usd.map(Unsigned::number).transpose()?,
        max_inflight_ops: input.max_inflight_ops,
        max_inference_tokens: input
            .max_inference_tokens
            .map(Unsigned::number)
            .transpose()?,
    })
}

pub(crate) fn parse(value: Option<Value>) -> Result<BudgetSpec, crate::service::ConsoleError> {
    let Some(value) = value else {
        return Ok(BudgetSpec::default());
    };
    let error = |error: serde_json::Error| {
        crate::service::ConsoleError::BadRequest(format!("invalid execution budget: {error}"))
    };
    deserialize(serde_json::to_value(value).map_err(error)?).map_err(error)
}

pub(crate) fn value(budget: &BudgetSpec) -> Result<Value, crate::service::ConsoleError> {
    crate::service::serde_value(Output::from(budget))
}
