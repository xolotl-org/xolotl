//! Discovery and output admission share the same execution lifecycle contract.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum ExecutionMode {
    Call,
    Subscription,
    Submission,
}

impl ExecutionMode {
    pub(super) fn supports_output(self, output: OutputMode) -> bool {
        match output {
            OutputMode::Unary | OutputMode::SinkOnly | OutputMode::Collect { .. } => true,
            OutputMode::Stream => matches!(self, Self::Subscription | Self::Submission),
            OutputMode::AsyncProcess => matches!(self, Self::Submission),
        }
    }

    fn describe(self, config: &crate::ConsoleRuntimeConfig, accepting_submissions: bool) -> Value {
        let (mode, owner, entries) = match self {
            Self::Call => (
                "call",
                "request",
                [
                    protocol::ACTION_RUNTIME_OPERATION_INVOKE,
                    protocol::ACTION_RUNTIME_PROGRAM_RUN,
                ],
            ),
            Self::Subscription => (
                "subscription",
                "subscription",
                [
                    protocol::STREAM_RUNTIME_OPERATION,
                    protocol::STREAM_RUNTIME_PROGRAM,
                ],
            ),
            Self::Submission => (
                "submission",
                "service",
                [
                    protocol::ACTION_RUNTIME_OPERATION_SUBMIT,
                    protocol::ACTION_RUNTIME_PROGRAM_SUBMIT,
                ],
            ),
        };
        let submission = matches!(self, Self::Submission);
        let enabled = config.enabled && (!submission || config.executions.enabled);
        let accepting = enabled && (!submission || accepting_submissions);
        // Collect is an adapter with a per-call limit, not a Method output bit.
        // Its nonzero representative tests lifecycle support only; admission
        // separately enforces the configured collection bound.
        let outputs = [
            ("unary", OutputMode::Unary),
            ("collect", OutputMode::Collect { limit: 1 }),
            ("sink_only", OutputMode::SinkOnly),
            ("stream", OutputMode::Stream),
            ("async_process", OutputMode::AsyncProcess),
        ];
        map_value([
            ("mode", Value::string(mode.into())),
            ("lifetime", Value::string("host".into())),
            ("owner", Value::string(owner.into())),
            ("enabled", Value::boolean(enabled)),
            ("accepting", Value::boolean(accepting)),
            (
                "entries",
                Value::list(
                    entries
                        .into_iter()
                        .map(|entry| Value::string(entry.into()))
                        .collect(),
                ),
            ),
            (
                "output_modes",
                Value::list(
                    outputs
                        .into_iter()
                        .filter(|(_, output)| self.supports_output(*output))
                        .map(|(name, _)| Value::string(name.into()))
                        .collect(),
                ),
            ),
        ])
    }
}

pub(super) fn describe(state: &ConsoleState) -> Value {
    let accepting = state.executions.accepting();
    Value::list(
        [
            ExecutionMode::Call,
            ExecutionMode::Subscription,
            ExecutionMode::Submission,
        ]
        .into_iter()
        .map(|mode| mode.describe(&state.runtime.config, accepting))
        .collect(),
    )
}
