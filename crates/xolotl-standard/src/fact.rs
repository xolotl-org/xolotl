//! Fact read-side Driver: `state://fact` / `state://fact/<process>/*`.
//!
//! Facts are the kernel-written operation records. The read side is a
//! capability-gated, **read-only** projection: `state://fact`
//! lists the append stream for audit / billing / trace projectors, while
//! `state://fact/<process>` lists one process for why-not / replay tooling.
//! Reads return explicit bounded pages; the projection never mutates Fact storage.

use async_trait::async_trait;
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, FactSink, MethodSpec, SharedFactStore,
};
use xolotl_types::{Failure, MethodId, Outcome, OutputMode, ProcessId, Purity, Value};

/// Method names in registration order for `state://fact/*`. Read-only:
/// `read` is an Observation (it reflects external/durable state), not Pure, so
/// its outcome is recorded when it feeds control flow.
pub(crate) const FACT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

/// Drives `state://fact/*` over the kernel's [`SharedFactStore`].
pub(crate) struct FactDriver {
    facts: FactSink,
}

impl FactDriver {
    /// Create a fact read-side projection driver backed by a shared fact store.
    pub(crate) fn new(facts: SharedFactStore) -> Self {
        Self {
            facts: FactSink::new(facts),
        }
    }
}

pub(crate) mod read;

#[async_trait]
impl Driver for FactDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let Some(path) = ctx.target_path.as_ref() else {
            return Ok(DriverOutput::new(Outcome::Fail(Failure::InvalidInput {
                reason: "fact read has no bound path".into(),
            })));
        };
        let scope = match fact_path_scope(path) {
            Ok(scope) => scope,
            Err(failure) => return Ok(DriverOutput::new(Outcome::Fail(failure))),
        };
        let mut query = read::parse_query(input, xolotl_kernel::FactOrder::Forward, 64)?;
        query.process = match scope {
            FactScope::All => None,
            FactScope::Process(process) => Some(process),
        };
        let page = self
            .facts
            .scan(query)
            .map_err(|error| DriverError::Other(error.to_string()))?;
        Ok(DriverOutput::new(Outcome::Done(read::page_value(
            query, page,
        ))))
    }
}

enum FactScope {
    All,
    Process(ProcessId),
}

fn fact_path_scope(path: &xolotl_types::Path) -> Result<FactScope, Failure> {
    let segs = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segs.first().map(|s| s.as_str()) != Some("fact")
    {
        return Err(Failure::InvalidInput {
            reason: "fact read target must be state://fact or state://fact/<process>".into(),
        });
    }
    match (segs.get(1), segs.get(2)) {
        (None, None) => Ok(FactScope::All),
        (Some(raw), None) => raw
            .as_str()
            .parse::<u64>()
            .map(ProcessId::new)
            .map(FactScope::Process)
            .map_err(|_error| Failure::InvalidInput {
                reason: "fact process scope must be a numeric process id".into(),
            }),
        _ => Err(Failure::InvalidInput {
            reason: "fact read target must be state://fact or state://fact/<process>".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use std::collections::BTreeMap;
    use xolotl_kernel::FactSink;
    use xolotl_types::{
        DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
        OperationId, ReplayClass, ResourceId, Timestamp,
    };

    fn fact(process: ProcessId, pos: u32) -> Fact {
        Fact {
            id: OperationId::new(
                process,
                ExecutionId::FIRST,
                InvocationId::new(u64::from(pos) + 1),
                NodeId::new(pos),
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input: Value::null(),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome: Some(Value::null()),
            batch: None,
            replay: ReplayClass::Observation,
            timestamp: Timestamp::millis(0),
        }
    }

    fn ctx_with_target(target: &str) -> Result<DriverContext> {
        let path = xolotl_types::Path::parse(target).with_context(|| format!("parse {target}"))?;
        Ok(DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_target_path(path))
    }

    #[tokio::test]
    async fn paged_read_preserves_physical_cursors_and_freezes_later_appends() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))?;
        sink.complete(fact(ProcessId::new(2), 2))?;
        let last = fact(ProcessId::new(1), 3);
        sink.complete(last.clone())?;
        let driver = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact/1")?;
        let mut input = BTreeMap::from([
            ("limit".into(), Value::integer(1)),
            ("max_examined".into(), Value::integer(1)),
            ("order".into(), Value::string("reverse".into())),
        ]);
        let Outcome::Done(first_value) = driver
            .call(
                MethodId::new(0),
                Value::map(input.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await?
            .outcome
        else {
            bail!("expected first page")
        };
        let first = first_value.as_map().context("expected map")?;
        ensure!(first.get("next") == Some(&Value::string("2".into())));
        let Some(rows) = first.get("items").and_then(Value::as_list) else {
            bail!("missing rows")
        };
        ensure!(rows.len() == 1);
        let Some(row) = rows.get(0).and_then(Value::as_map) else {
            bail!("missing row")
        };
        ensure!(row.get("op_id") == Some(&Value::string(last.id.to_string())));
        sink.complete(fact(ProcessId::new(1), 4))?;

        input.insert(
            "before".into(),
            first.get("next").context("missing cursor")?.clone(),
        );
        let Outcome::Done(second_value) = driver
            .call(
                MethodId::new(0),
                Value::map(input.clone()),
                OutputMode::Unary,
                &ctx,
            )
            .await?
            .outcome
        else {
            bail!("expected filtered page")
        };
        let second = second_value.as_map().context("expected map")?;
        ensure!(second.get("items") == Some(&Value::list(vec![])));
        ensure!(second.get("complete") == Some(&Value::boolean(false)));
        ensure!(second.get("next") == Some(&Value::string("1".into())));
        input.insert(
            "before".into(),
            second.get("next").context("missing cursor")?.clone(),
        );
        let Outcome::Done(third_value) = driver
            .call(MethodId::new(0), Value::map(input), OutputMode::Unary, &ctx)
            .await?
            .outcome
        else {
            bail!("expected terminal page")
        };
        let third = third_value.as_map().context("expected map")?;
        ensure!(third.get("complete") == Some(&Value::boolean(true)));
        ensure!(third.get("next") == Some(&Value::null()));
        Ok(())
    }

    #[tokio::test]
    async fn read_rejects_invalid_budgets_and_oversized_records() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))?;
        let driver = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact")?;
        for (name, value) in [
            ("limit", Value::integer(0)),
            ("limit", Value::integer(257)),
            ("max_examined", Value::integer(0)),
            ("max_bytes", Value::integer(262145)),
            ("from", Value::integer(-1)),
            ("before", Value::string("18446744073709551616".into())),
            ("order", Value::string("timestamp".into())),
            ("unknown", Value::integer(1)),
        ] {
            let result = driver
                .call(
                    MethodId::new(0),
                    Value::map(BTreeMap::from([(name.into(), value)])),
                    OutputMode::Unary,
                    &ctx,
                )
                .await;
            ensure!(matches!(result, Err(DriverError::InvalidInput(_))));
        }
        ensure!(
            driver
                .call(
                    MethodId::new(0),
                    Value::map(BTreeMap::from([("max_bytes".into(), Value::integer(1)),])),
                    OutputMode::Unary,
                    &ctx
                )
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_returns_empty_for_unknown_process() -> Result<()> {
        let (_sink, store) = FactSink::in_memory();
        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact/99")?;
        let out = d
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await
            .context("read unknown process facts")?;
        let Outcome::Done(page_value) = out.outcome else {
            bail!("expected fact page")
        };
        let page = page_value.as_map().context("expected map")?;
        ensure!(page.get("items") == Some(&Value::list(vec![])));
        ensure!(page.get("next") == Some(&Value::null()));
        Ok(())
    }

    #[tokio::test]
    async fn root_fact_path_lists_global_stream() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write first fact")?;
        sink.complete(fact(ProcessId::new(2), 1))
            .context("write second fact")?;

        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact")?;
        let out = d
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await
            .context("read global facts")?;
        let Outcome::Done(page_value) = out.outcome else {
            bail!("expected fact page")
        };
        let page = page_value.as_map().context("expected map")?;
        let Some(rows) = page.get("items").and_then(Value::as_list) else {
            bail!("missing page items")
        };
        ensure!(rows.len() == 2, "global fact count: {}", rows.len());
        Ok(())
    }

    #[tokio::test]
    async fn process_fact_path_filters_one_process() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write first fact")?;
        sink.complete(fact(ProcessId::new(2), 1))
            .context("write second fact")?;

        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact/2")?;
        let out = d
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await
            .context("read process facts")?;
        let Outcome::Done(page_value) = out.outcome else {
            bail!("expected fact page")
        };
        let page = page_value.as_map().context("expected map")?;
        let Some(rows) = page.get("items").and_then(Value::as_list) else {
            bail!("missing page items")
        };
        ensure!(rows.len() == 1, "process fact count: {}", rows.len());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_fact_scope_is_rejected_not_fallback() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write fact")?;
        let d = FactDriver::new(store);

        for target in [
            "state://fact/not-a-process",
            "state://fact/1/extra",
            "path://remote/state/fact/1",
        ] {
            let ctx = ctx_with_target(target)?;
            let out = d
                .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
                .await
                .with_context(|| format!("read malformed target {target}"))?;
            ensure!(
                matches!(out.outcome, Outcome::Fail(Failure::InvalidInput { .. })),
                "malformed fact target must fail: {target}"
            );
        }
        Ok(())
    }
}
