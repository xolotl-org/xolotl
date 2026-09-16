//! Kernel process inspection driver.

use async_trait::async_trait;
use std::collections::BTreeMap;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, Outcome, OutputMode, ProcessId, Purity, Value};

/// `effect://kernel/process/inspect`.
pub(crate) const INSPECT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("inspect", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

/// Driver backing `effect://kernel/process/inspect`.
pub(crate) struct KernelInspectDriver {
    processes: xolotl_kernel::ProcessTable,
    facts: xolotl_kernel::FactSink,
}

impl KernelInspectDriver {
    /// Create an inspect driver over process and fact state.
    pub(crate) fn new(
        processes: xolotl_kernel::ProcessTable,
        facts: xolotl_kernel::FactSink,
    ) -> Self {
        Self { processes, facts }
    }
}

#[async_trait]
impl Driver for KernelInspectDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let mut input = crate::input::map(input, "inspect")?;
        let process = crate::fact::read::take_cursor(&mut input, "process")?.map(ProcessId::new);
        let include_facts = match input
            .remove("include_recent_facts")
            .as_ref()
            .map(Value::view)
        {
            None => false,
            Some(xolotl_types::ValueView::Bool(value)) => value,
            Some(_) => {
                return Err(DriverError::InvalidInput(
                    "inspect.include_recent_facts must be a boolean".into(),
                ));
            }
        };
        if include_facts && process.is_none() {
            return Err(DriverError::InvalidInput(
                "inspect.include_recent_facts requires an explicit process".into(),
            ));
        }
        let query = crate::fact::read::parse_query(
            Value::from(input),
            xolotl_kernel::FactOrder::Reverse,
            32,
        )?;

        let ids = match process {
            Some(pid) => vec![pid],
            None => self.processes.all_ids(),
        };
        let mut rows = Vec::with_capacity(ids.len());
        for pid in ids {
            let mut row = BTreeMap::new();
            row.insert("process".into(), Value::string(pid.get().to_string()));
            if let Some(status) = self.processes.status(pid) {
                row.insert("status".into(), Value::string(format!("{status:?}")));
                row.insert("terminal".into(), Value::boolean(status.is_terminal()));
            } else {
                row.insert("status".into(), Value::string("Unknown".into()));
            }
            if let Some(identity) = self.processes.identity(pid) {
                row.insert("identity".into(), Value::string(identity.get().to_string()));
            }
            let children = self
                .processes
                .children_of(pid)
                .into_iter()
                .map(|child| Value::string(child.get().to_string()))
                .collect();
            row.insert("children".into(), Value::list(children));
            if include_facts {
                let query = xolotl_kernel::FactQuery {
                    process: Some(pid),
                    ..query
                };
                let page = self
                    .facts
                    .scan(query)
                    .map_err(|error| DriverError::Other(error.to_string()))?;
                row.insert(
                    "recent_facts".into(),
                    crate::fact::read::page_value(query, page),
                );
            }
            rows.push(Value::map(row));
        }
        Ok(DriverOutput::new(Outcome::Done(Value::list(rows))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use xolotl_kernel::Bootstrap;
    use xolotl_types::IdentityRef;

    #[derive(Default)]
    struct RejectFactReads(xolotl_kernel::InMemoryExecutionIdSource);

    impl xolotl_kernel::ExecutionIdSource for RejectFactReads {
        fn reserve(
            &self,
            count: std::num::NonZeroU64,
        ) -> Result<xolotl_kernel::ExecutionIdRange, xolotl_kernel::ExecutionIdError> {
            self.0.reserve(count)
        }
    }

    impl xolotl_kernel::FactStore for RejectFactReads {
        fn append(&self, _fact: xolotl_types::Fact) -> Result<u64, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected append".into()))
        }
        fn complete(&self, _fact: xolotl_types::Fact) -> Result<(), xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected complete".into()))
        }
        fn sync(&self) -> Result<(), xolotl_kernel::FactError> {
            Ok(())
        }
        fn scan(
            &self,
            _query: xolotl_kernel::FactQuery,
        ) -> Result<xolotl_kernel::FactPage, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected fact read".into()))
        }
        fn lookup(
            &self,
            _query: xolotl_kernel::FactLookup,
        ) -> Result<xolotl_kernel::FactLookupResult, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected fact read".into()))
        }
        fn facts_of(
            &self,
            _process: ProcessId,
        ) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected fact read".into()))
        }
        fn all_facts(&self) -> Result<Vec<xolotl_types::Fact>, xolotl_kernel::FactError> {
            Err(xolotl_kernel::FactError("unexpected fact read".into()))
        }
        fn cursor(&self) -> u64 {
            0
        }
    }

    #[tokio::test]
    async fn process_metadata_does_not_require_fact_storage() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let driver = KernelInspectDriver::new(
            boot.kernel.processes.clone(),
            xolotl_kernel::FactSink::new(std::sync::Arc::new(RejectFactReads::default())),
        );
        let ctx = DriverContext::new(IdentityRef::ROOT, boot.root);
        let Outcome::Done(rows_value) = driver
            .call(MethodId::new(0), Value::null(), OutputMode::Unary, &ctx)
            .await?
            .outcome
        else {
            bail!("expected process rows")
        };
        let rows = rows_value.as_list().context("expected list")?;
        let Some(row) = rows.first().and_then(Value::as_map) else {
            bail!("missing process")
        };
        ensure!(row.get("fact_count").is_none() && row.get("recent_facts").is_none());
        let without_process = driver
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([(
                    "include_recent_facts".into(),
                    Value::boolean(true),
                )])),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(matches!(
            without_process,
            Err(DriverError::InvalidInput(message))
                if message == "inspect.include_recent_facts requires an explicit process"
        ));
        let with_process = driver
            .call(
                MethodId::new(0),
                Value::map(BTreeMap::from([
                    ("include_recent_facts".into(), Value::boolean(true)),
                    ("process".into(), Value::string(boot.root.get().to_string())),
                ])),
                OutputMode::Unary,
                &ctx,
            )
            .await;
        ensure!(matches!(
            with_process,
            Err(DriverError::Other(message)) if message == "fact store failed: unexpected fact read"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn inspect_lists_processes() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let out = d
            .call(
                MethodId::new(0),
                Value::null(),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await
            .context("inspect processes")?;
        let rows = match out.outcome {
            Outcome::Done(value) => value.into_list().context("expected process rows")?,
            other => bail!("expected rows, got {other:?}"),
        };
        ensure!(!rows.is_empty(), "expected at least one process row");
        Ok(())
    }

    #[tokio::test]
    async fn inspect_can_include_recent_facts() -> Result<()> {
        let boot = Bootstrap::in_memory();
        boot.record_gateway_audit(xolotl_kernel::GatewayAudit {
            event: "test",
            username: None,
            source_addr: None,
            outcome: "ok",
            mfa_level: None,
            details: None,
        })
        .context("record gateway audit")?;
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let mut input = BTreeMap::new();
        input.insert("include_recent_facts".into(), Value::boolean(true));
        input.insert("process".into(), Value::string(boot.root.get().to_string()));
        input.insert("limit".into(), Value::integer(8));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(input),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await
            .context("inspect recent facts")?;
        if !matches!(out.outcome, Outcome::Done(ref value) if value.as_list().is_some()) {
            bail!("expected rows, got {out:?}");
        };
        Ok(())
    }

    #[tokio::test]
    async fn inspect_rejects_malformed_include_recent_facts() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let mut input = BTreeMap::new();
        input.insert("include_recent_facts".into(), Value::string("yes".into()));
        let out = d
            .call(
                MethodId::new(0),
                Value::map(input),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await;
        ensure!(
            matches!(out, Err(DriverError::InvalidInput(ref message)) if message.contains("include_recent_facts")),
            "inspect accepted malformed include_recent_facts: {out:?}"
        );
        Ok(())
    }
}
