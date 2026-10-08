use super::{Config, Work};
use anyhow::{Context, ensure};
use std::hint::black_box;
use xolotl_graph::DoNode;
use xolotl_plan::{CompileLimits, Plan, PlanError, Step, compile_with_limits};
use xolotl_state::host::{encoded_size, source_payload_fingerprint_bounded};
use xolotl_types::{Path, Value};

pub struct SourceFingerprintCase {
    payload: Value,
    expected: Option<(usize, [u8; 32])>,
    budget: usize,
}

impl SourceFingerprintCase {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let payload = match config.case.as_str() {
            "source-fingerprint-deep-reject" => {
                let mut payload = Value::null();
                for _ in 0..config.depth.get() {
                    payload = Value::list(vec![payload]);
                }
                payload
            }
            "source-fingerprint-wide-reject" => {
                Value::list(vec![Value::null(); config.width.get()])
            }
            _ => Value::list(vec![Value::bytes(vec![255; 16 * 1024]); config.width.get()]),
        };
        let budget = config.window.get();
        let rejected = config.case != "source-fingerprint";
        let expected = if rejected {
            ensure!(
                source_payload_fingerprint_bounded(&payload, budget)?.is_none(),
                "rejection fixture fits the Source fingerprint budget"
            );
            None
        } else {
            let bytes = encoded_size(&xolotl_types::tagged_value::serializable(&payload))?;
            let fingerprint = source_payload_fingerprint_bounded(&payload, usize::MAX)?
                .context("unbounded fixture fingerprint was rejected")?;
            ensure!(fingerprint.0 == bytes, "fixture encoding size disagrees");
            ensure!(
                source_payload_fingerprint_bounded(&payload, budget)? == Some(fingerprint),
                "admitted fixture exceeds the Source fingerprint budget"
            );
            Some(fingerprint)
        };
        Ok(Self {
            payload,
            expected,
            budget,
        })
    }

    pub fn run(&self, config: &Config) -> anyhow::Result<Work> {
        ensure!(
            config.window.get() == self.budget,
            "fingerprint budget changed"
        );
        for _ in 0..config.work.get() {
            let result = source_payload_fingerprint_bounded(black_box(&self.payload), self.budget)?;
            ensure!(
                black_box(result) == self.expected,
                "fingerprint outcome changed"
            );
        }
        Ok(Work {
            units: config.work.get() as u64,
            unit: if self.expected.is_some() {
                "admitted bounded Source payload fingerprint with checked bytes and digest"
            } else {
                "bounded Source payload fingerprint capacity rejection"
            },
        })
    }
}

pub struct PlanCompileCase {
    source: Plan,
    rejected: bool,
    limits: CompileLimits,
    width: usize,
    depth: usize,
    identity: Path,
}

impl PlanCompileCase {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let mut steps = (0..config.width.get())
            .map(|_| Step::Pure {
                value: serde_json::json!(7),
            })
            .collect::<Vec<_>>();
        for _ in 0..config.depth.get() {
            steps = vec![Step::Acting {
                identity: "identity://runtime-bench/compiler".into(),
                body: steps,
            }];
        }
        let source = Plan {
            id: "runtime-bench".into(),
            version: 1,
            description: None,
            steps,
        };
        let limits = CompileLimits::default();
        let rejected = config.case == "plan-compile-reject";
        let case = Self {
            source,
            rejected,
            limits,
            width: config.width.get(),
            depth: config.depth.get(),
            identity: Path::parse("identity://runtime-bench/compiler")?,
        };
        if rejected {
            ensure!(
                matches!(
                    compile_with_limits(&case.source, limits),
                    Err(PlanError::Capacity)
                ),
                "rejection fixture did not exceed Plan compiler capacity"
            );
        } else {
            let compiled = compile_with_limits(&case.source, limits)
                .context("admitted Plan fixture failed")?;
            case.check_program(&compiled)?;
        }
        Ok(case)
    }

    pub fn run(&self, config: &Config) -> anyhow::Result<Work> {
        for _ in 0..config.work.get() {
            let compiled = compile_with_limits(black_box(&self.source), self.limits);
            if !self.rejected {
                let compiled = compiled.context("admitted Plan compilation failed")?;
                self.check_program(&compiled)?;
                drop(black_box(compiled));
            } else {
                ensure!(
                    matches!(compiled, Err(PlanError::Capacity)),
                    "Plan compiler rejection changed"
                );
            }
        }
        Ok(Work {
            units: config.work.get() as u64,
            unit: if !self.rejected {
                "bounded borrowed Plan compilation, iterative output validation and output release"
            } else {
                "bounded borrowed Plan compiler capacity rejection"
            },
        })
    }

    fn check_program(&self, mut node: &DoNode) -> anyhow::Result<()> {
        for _ in 0..self.depth {
            let DoNode::Acting { identity, body } = node else {
                anyhow::bail!("compiled Plan identity wrapper missing");
            };
            ensure!(identity == &self.identity, "compiled identity changed");
            node = body;
        }
        for remaining in (2..=self.width).rev() {
            let DoNode::Let { name, value, body } = node else {
                anyhow::bail!("compiled Plan sequence node missing");
            };
            ensure!(
                name.strip_prefix("_plan_sequence_")
                    .and_then(|index| index.parse::<usize>().ok())
                    == Some(remaining - 2),
                "compiled sequence order changed"
            );
            check_literal(body)?;
            node = value;
        }
        check_literal(node)
    }
}

fn check_literal(node: &DoNode) -> anyhow::Result<()> {
    ensure!(
        matches!(node, DoNode::Pure(value) if value.as_int() == Some(7)),
        "compiled literal changed"
    );
    Ok(())
}
