//! Fixed stream discovery contracts.

use super::actions::{
    authority, execution_budget_schema, field, schema, unresolved_operations_schema,
};
use super::*;

/// Borrow the immutable stream contracts shared by discovery and admission.
///
/// The catalog is initialized once per process. Use [`registry_snapshot`] when
/// an independently owned catalog is needed.
pub fn stream_descriptors() -> &'static [StreamDescriptor] {
    static STREAM_DESCRIPTORS: OnceLock<Vec<StreamDescriptor>> = OnceLock::new();
    STREAM_DESCRIPTORS.get_or_init(build_stream_descriptors)
}

fn build_stream_descriptors() -> Vec<StreamDescriptor> {
    let mut descriptors = vec![
        StreamDescriptor {
            id: STREAM_STATE_WATCH.into(),
            domain: "visibility".into(),
            visibility: VisibilityTier::BusinessData,
            requires_step_up: true,
            authority_templates: vec![authority("subscribe", "state://**")],
            input: schema(
                "stream.state_watch.input",
                "map",
                vec![field("pattern", "path-pattern", true)],
                vec![
                    "vault patterns are rejected; secret.catalog exposes metadata only",
                    "business-data streams require StreamCall.scope, justification, and ttl_ms",
                    "streams deliver live notifications without history replay",
                ],
            ),
            event: schema(
                "stream.state_watch.event",
                "console_event",
                vec![],
                vec![
                    "state_drop_prefix_append removes an exact list prefix and appends one item; resnapshot on lag",
                ],
            ),
        },
        StreamDescriptor {
            id: STREAM_AUDIT_FACTS.into(),
            domain: "audit".into(),
            visibility: VisibilityTier::ProtectedPayload,
            requires_step_up: true,
            authority_templates: vec![authority("read", "state://fact/**")],
            input: schema(
                "stream.audit_facts.input",
                "map",
                vec![
                    field("process", "decimal_u64", false),
                    field("max_bytes", "positive_usize", false),
                ],
                vec![
                    "audit/fact streams require StreamCall.scope, justification, and ttl_ms",
                    "streams deliver live notifications without history replay",
                    "only notifications after subscription are observed; historical rows require explicit bounded page reads",
                    "append and completion notifications emit current records as upserts by op_id; completed indicates outcome availability",
                    "process filters the current caller before checking the byte budget; unrelated records do not consume that budget",
                    "lag or an oversized matching record closes the stream; resynchronize with bounded fact pages and subscribe again",
                    "each event contains one record",
                ],
            ),
            event: schema("stream.audit_facts.event", "console_event", vec![], vec![]),
        },
    ];
    for action in action_descriptors().iter().filter(|action| {
        matches!(
            action.id.as_str(),
            ACTION_RUNTIME_OPERATION_INVOKE | ACTION_RUNTIME_PROGRAM_RUN
        )
    }) {
        let id = if action.id == ACTION_RUNTIME_OPERATION_INVOKE {
            STREAM_RUNTIME_OPERATION
        } else {
            STREAM_RUNTIME_PROGRAM
        };
        let mut input = action.input.clone();
        input.schema_id = format!("{id}.input");
        input.notes = vec![
            "requires scope, justification and ttl_ms; subscription owns execution and dropping it cancels remaining work".into(),
            "operation output defaults to stream; programs select output per operation; unary, sink_only and bounded collect may be composed with streams".into(),
            "same import preflight, capability ceilings and execution budgets as runtime calls; no replay, reconnect or automatic retry".into(),
            "runtime.describe reports output port and chunk windows; blocked delivery counts toward the execution deadline".into(),
        ];
        descriptors.push(StreamDescriptor {
            id: id.into(),
            domain: "runtime".into(),
            visibility: VisibilityTier::ProtectedPayload,
            requires_step_up: true,
            authority_templates: vec![],
            input,
            event: runtime_event_schema(),
        });
    }
    descriptors
}

fn runtime_event_schema() -> SchemaDescriptor {
    let mut event = schema(
        "runtime.stream.event",
        "map",
        vec![],
        vec![
            "per-operation chunks precede operation_finished; every port is drained before finished; parallel ports may interleave",
            "timeouts, cancellation, loss of authority and delivery failures can close before finished; previously committed effects remain",
        ],
    );
    event.discriminator = Some("kind".into());
    for (kind, mut fields) in [
        (
            "started",
            vec![
                field("process_id", "decimal_u64", true),
                field("program_id", "string", true),
                field("budget", "execution_budget", true),
            ],
        ),
        (
            "output",
            vec![
                field("operation_id", "string", true),
                field("value", "value", true),
                field("taint", "value", true),
            ],
        ),
        (
            "operation_finished",
            vec![
                field("operation_id", "string", true),
                field("failure", "value", true),
                field("taint", "value", true),
                field("origin", "string", true),
            ],
        ),
        (
            "finished",
            vec![
                field("process_id", "decimal_u64", true),
                field("program_id", "string", true),
                field("budget", "execution_budget", true),
                field("outcome", "string", true),
                field("value", "value", true),
                field("failure", "value", true),
                field("taint", "value", true),
                field("unresolved_operations", "unresolved_operations", true),
            ],
        ),
    ] {
        fields.insert(0, field("kind", "string", true));
        let id = format!("runtime.stream.{kind}");
        event.variants.insert(kind.into(), id.clone());
        event.definitions.push(schema(&id, "map", fields, vec![
            "failure is null or a sanitized ConsoleFailure; outcome is done, short or failed; origin is current_attempt or cached_outcome",
        ]));
    }
    event.definitions.push(execution_budget_schema());
    event.definitions.push(unresolved_operations_schema());
    event
}
