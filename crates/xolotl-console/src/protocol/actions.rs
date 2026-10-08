//! Fixed action and schema discovery contracts.

use super::*;

/// Borrow the immutable action contracts shared by discovery and admission.
///
/// The catalog is initialized once per process. Use [`registry_snapshot`] when
/// an independently owned catalog is needed.
pub fn action_descriptors() -> &'static [ActionDescriptor] {
    static ACTION_DESCRIPTORS: OnceLock<Vec<ActionDescriptor>> = OnceLock::new();
    ACTION_DESCRIPTORS.get_or_init(|| {
        let mut descriptors = build_action_descriptors();
        descriptors.extend(runtime_descriptors());
        descriptors.extend(federation_descriptors());
        for descriptor in &mut descriptors {
            if descriptor.id == ACTION_STATE_SNAPSHOT {
                descriptor.input.definitions = vec![snapshot_section_schema()];
            }
            if management_list_action(&descriptor.id) || matches!(descriptor.id.as_str(), ACTION_VISIBILITY_STATE_LIST | ACTION_ACCESS_SESSION_LIST) {
                descriptor.input.fields.extend([
                    field("limit", "positive_usize", false),
                    field("cursor", "string", false),
                    field("max_bytes", "positive_usize", false),
                ]);
                descriptor.input.value_kind = "map".into();
                descriptor.output = schema(
                    &format!("{}.page", descriptor.id),
                    "map",
                    vec![
                        field("entries", if descriptor.id == ACTION_ACCESS_SESSION_LIST { "list<session_summary>" } else { "list<state_entry>" }, true),
                        field("next_cursor", "string|null", true),
                    ],
                    vec![
                        "opaque next_cursor is returned as cursor for the same action and prefix; null ends the scan",
                        "pages observe live state and are bounded by entry, byte, and backend work budgets",
                    ],
                );
                if descriptor.id == ACTION_ACCESS_SESSION_LIST {
                    descriptor.output.definitions.push(schema(
                        "session_summary",
                        "map",
                        vec![
                            field("sid", "string", true),
                            field("username", "string", true),
                            field("identity_path", "path", true),
                            field("authentication", "authentication_evidence", true),
                            field("issued_at", "i64", true),
                            field("authenticated_at", "i64", true),
                            field("expires_at", "i64", true),
                            field("idle_expires_at", "i64", true),
                            field("mfa_level", "u8", true),
                            field("last_seen", "i64", true),
                            field("source_addr", "string", true),
                        ],
                        vec![
                            "timestamps are Unix milliseconds",
                            "authentication is the retained proof evidence; mfa_level and authenticated_at are derived summaries",
                            "issued_at records this session's creation; authenticated_at is the latest proof verification time",
                            "credential management and refresh preserve complete evidence; refresh also preserves issued_at and hard expiry",
                        ],
                    ));
                    descriptor.output.definitions.push(authentication_evidence_schema());
                }
            }
        }
        descriptors
    })
}

pub(crate) fn management_list_action(id: &str) -> bool {
    matches!(
        id,
        ACTION_CONFIG_LIST
            | ACTION_ACCESS_USER_LIST
            | ACTION_ACCESS_ROLE_LIST
            | ACTION_EXTERNAL_INSTALLATION_LIST
            | ACTION_EXTERNAL_MANIFEST_LIST
            | ACTION_PROJECTION_IN_PROCESS_STATUS_LIST
            | ACTION_INFERENCE_BACKEND_LIST
            | ACTION_INFERENCE_MODEL_LIST
            | ACTION_INFERENCE_GROUP_LIST
    )
}

fn federation_descriptors() -> Vec<ActionDescriptor> {
    let peer = field("peer_node", "string", true);
    let export = field("export", "string", true);
    let revision = field("expected_revision", "decimal_u64|null", false);
    let read_policy = ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false);
    let write_policy =
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true);
    let peer_authority = crate::paths::FEDERATION_PEERS_AUTHORITY;
    vec![
        action(
            ACTION_FEDERATION_PEER_READ,
            "federation",
            ActionKind::View,
            read_policy.clone(),
            vec![authority("read", peer_authority)],
            schema(
                "federation.peer.read.input",
                "map",
                vec![peer.clone()],
                vec![],
            ),
            federation_read_output("federation.peer.read.output", peer_authority_schema()),
        ),
        action(
            ACTION_FEDERATION_PEER_LIST,
            "federation",
            ActionKind::View,
            read_policy.clone(),
            vec![authority("read", peer_authority)],
            schema(
                "federation.peer.list.input",
                "map",
                vec![
                    field("limit", "positive_usize", false),
                    field("cursor", "string", false),
                ],
                vec![
                    "cursor is the exclusive lowercase hexadecimal node ID; pages may reflect concurrent changes",
                    "limit defaults to 64 and accepts 1 through 255 entries",
                ],
            ),
            federation_page_output("federation.peer.list.output", peer_authority_schema()),
        ),
        action(
            ACTION_FEDERATION_PEER_WRITE_CAS,
            "federation",
            ActionKind::Mutation,
            write_policy.clone(),
            vec![authority("write", peer_authority)],
            schema(
                "federation.peer.write_cas.input",
                "map",
                vec![
                    peer.clone(),
                    field("enabled", "bool", true),
                    revision.clone(),
                ],
                vec![
                    "only application-owned rows are writable; a manifest-owned row is rejected atomically",
                ],
            ),
            federation_revision_output("federation.peer.write_cas.output"),
        ),
        action(
            ACTION_FEDERATION_PEER_ADMISSION_READ,
            "federation",
            ActionKind::View,
            read_policy.clone(),
            vec![authority("read", peer_authority)],
            schema(
                "federation.peer_admission.read.input",
                "map",
                vec![peer.clone()],
                vec![],
            ),
            federation_read_output(
                "federation.peer_admission.read.output",
                peer_admission_schema(),
            ),
        ),
        action(
            ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS,
            "federation",
            ActionKind::Mutation,
            write_policy.clone(),
            vec![authority("write", peer_authority)],
            schema(
                "federation.peer_admission.write_cas.input",
                "map",
                vec![
                    peer.clone(),
                    field("minimum_online_generation", "decimal_u64", true),
                    field("allowed_authorization_digests", "list<string>", true),
                    revision.clone(),
                ],
                vec![
                    "accepts at most eight exact SHA-384 digests of root-signed online authorizations",
                    "the store atomically rejects changes to manifest-owned peer admission",
                ],
            ),
            federation_revision_output("federation.peer_admission.write_cas.output"),
        ),
        action(
            ACTION_FEDERATION_EXPORT_READ,
            "federation",
            ActionKind::View,
            read_policy.clone(),
            vec![authority("read", peer_authority)],
            schema(
                "federation.export.read.input",
                "map",
                vec![peer.clone(), export.clone()],
                vec![],
            ),
            federation_read_output("federation.export.read.output", export_authority_schema()),
        ),
        action(
            ACTION_FEDERATION_EXPORT_LIST,
            "federation",
            ActionKind::View,
            read_policy,
            vec![authority("read", peer_authority)],
            schema(
                "federation.export.list.input",
                "map",
                vec![
                    peer.clone(),
                    field("limit", "positive_usize", false),
                    field("cursor", "string", false),
                ],
                vec![
                    "cursor is the exclusive literal export name; pages may reflect concurrent changes",
                    "limit defaults to 64 and accepts 1 through 255 entries",
                ],
            ),
            federation_page_output("federation.export.list.output", export_authority_schema()),
        ),
        action(
            ACTION_FEDERATION_EXPORT_WRITE_CAS,
            "federation",
            ActionKind::Mutation,
            write_policy,
            vec![authority("write", peer_authority)],
            schema(
                "federation.export.write_cas.input",
                "map",
                vec![
                    peer,
                    export,
                    field("serve", "bool", true),
                    field("receive", "bool", true),
                    revision,
                ],
                vec!["only application-owned rows are writable; each direction is explicit"],
            ),
            federation_revision_output("federation.export.write_cas.output"),
        ),
    ]
}

fn federation_read_output(id: &str, entry: SchemaDescriptor) -> SchemaDescriptor {
    let mut output = schema(id, &format!("{}|null", entry.schema_id), vec![], vec![]);
    output.definitions.push(entry);
    output
}

fn federation_page_output(id: &str, entry: SchemaDescriptor) -> SchemaDescriptor {
    let mut output = schema(
        id,
        "map",
        vec![
            field("entries", &format!("list<{}>", entry.schema_id), true),
            field("next_cursor", "string|null", true),
        ],
        vec![],
    );
    output.definitions.push(entry);
    output
}

fn federation_revision_output(id: &str) -> SchemaDescriptor {
    schema(
        id,
        "map",
        vec![field("revision", "decimal_u64", true)],
        vec![],
    )
}

fn peer_authority_schema() -> SchemaDescriptor {
    schema(
        "federation_peer_authority",
        "map",
        vec![
            field("peer_node", "string", true),
            field("revision", "decimal_u64", true),
            field("enabled", "bool", true),
            field("owner", "application|manifest", true),
        ],
        vec![],
    )
}

fn peer_admission_schema() -> SchemaDescriptor {
    schema(
        "federation_peer_admission",
        "map",
        vec![
            field("peer_node", "string", true),
            field("revision", "decimal_u64", true),
            field("minimum_online_generation", "decimal_u64", true),
            field("allowed_authorization_digests", "list<string>", true),
            field("owner", "application|manifest", true),
        ],
        vec![],
    )
}

fn export_authority_schema() -> SchemaDescriptor {
    schema(
        "federation_export_authority",
        "map",
        vec![
            field("peer_node", "string", true),
            field("export", "string", true),
            field("revision", "decimal_u64", true),
            field("serve", "bool", true),
            field("receive", "bool", true),
            field("owner", "application|manifest", true),
        ],
        vec![],
    )
}

fn runtime_descriptors() -> Vec<ActionDescriptor> {
    let mut descriptors = vec![
        action(
            ACTION_RUNTIME_DESCRIBE,
            "runtime",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("runtime.describe.input", "null", vec![], vec![]),
            runtime_description_schema(),
        ),
        action(
            ACTION_RUNTIME_RESOURCE_DESCRIBE,
            "runtime",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "runtime.resource.describe.input",
                "map",
                vec![field("target", "path", true)],
                vec![],
            ),
            schema(
                "runtime.resource.describe.output",
                "map",
                vec![
                    field("target", "path", true),
                    field("resource_id", "decimal_u64", true),
                    field("interfaces", "list<value>", true),
                    field("advisory", "bool", true),
                ],
                vec![
                    "live kernel interface/method contracts filtered by host exposure and caller capabilities; residual policy is checked at invocation",
                ],
            ),
        ),
    ];
    for (id, mut fields) in [
        (
            ACTION_RUNTIME_OPERATION_INVOKE,
            vec![
                field("target", "path", true),
                field("method", "string", true),
                field("output", "string", false),
                field("collect_limit", "positive_usize", false),
            ],
        ),
        (
            ACTION_RUNTIME_PROGRAM_RUN,
            vec![field("source", "string", true)],
        ),
        (
            ACTION_RUNTIME_OPERATION_SUBMIT,
            vec![
                field("target", "path", true),
                field("method", "string", true),
                field("output", "string", false),
                field("collect_limit", "positive_usize", false),
            ],
        ),
        (
            ACTION_RUNTIME_PROGRAM_SUBMIT,
            vec![field("source", "string", true)],
        ),
    ] {
        fields.extend([
            field("input", "value", false),
            field("timeout_ms", "u64", false),
            field("budget", "execution_budget", false),
        ]);
        let mut descriptor = action(
            id,
            "runtime",
            ActionKind::Mutation,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![],
            schema(
                &format!("{id}.input"),
                "map",
                fields,
                vec![
                    "requires scope, justification and ttl_ms; runtime.describe reports public host enablement and limits, while module manifests are projected for the caller",
                    "every operation is preflighted using its kernel method capability verb before any effects; residual policy remains per operation",
                    "source is portable Program v1 JSON with its native tagged constants; input uses the lossless Console Value",
                    "unary, sink_only, bounded collect, delegated acting scopes, authorized signals and host modules are supported; async_process requires submission and explicit spawn-with authority; Stream submissions retain a bounded host-lifetime output log",
                    "reserved kernel, vault and Fact resources require dedicated management actions; cancellation and failure do not roll back completed effects",
                ],
            ),
            schema(
                &format!("{id}.output"),
                "map",
                vec![
                    field("process_id", "decimal_u64", true),
                    field("program_id", "string", true),
                    field("budget", "execution_budget", true),
                    field("outcome", "string", true),
                    field("value", "value", true),
                    field("taint", "value", true),
                ],
                vec![
                    "program_id identifies compiled content, not execution identity; process_id identifies this execution",
                ],
            ),
        );
        descriptor.input.definitions.push(execution_budget_schema());
        descriptor
            .output
            .definitions
            .push(execution_budget_schema());
        if matches!(
            id,
            ACTION_RUNTIME_OPERATION_SUBMIT | ACTION_RUNTIME_PROGRAM_SUBMIT
        ) {
            descriptor.input.fields.push(field(
                "submission_identity",
                "submission_identity",
                false,
            ));
            descriptor
                .input
                .definitions
                .push(submission_identity_schema());
            descriptor.input.notes.extend([
                "submission_identity explicitly opts into response-loss retry protection; without it distinct fire-and-forget submissions remain nonidempotent and require no submission history".into(),
                "guarded retries bind the immutable owning account and the original request; changing the request under the same identity is rejected without dispatch".into(),
                "preparing excludes concurrent dispatch but is not acceptance; unproven is not proof of no effects and never authorizes blind replay".into(),
            ]);
            descriptor.input.notes.push("submission survives disconnect and logout; timeout_ms and the host runtime duration ceiling fix its execution deadline, while ttl_ms bounds pre-accept asynchronous checks and immediate visibility; account/credential generation or required role authority changes cancel it within the configured check bounds".into());
            let mut output_fields = execution_record_fields();
            for output_field in &mut output_fields {
                if output_field.name != "execution" {
                    output_field.required = false;
                }
            }
            output_fields.push(field("submission_evidence", "accepted|retired", false));
            descriptor.output = execution_output_schema(
                &format!("{id}.output"),
                output_fields,
                vec![
                    "acceptance reserves running and result capacity; execution_id identifies the retained record across adapters",
                    "lifetime is host; submissions survive observer disconnect, not host restart; a lost acceptance response does not justify blind resubmission",
                    "results preserve unresolved effect identities; cancellation does not prove rollback",
                    "first guarded acceptance returns full job metadata and submission_evidence=accepted; existing guarded retries return the original ActionResult.execution and only {execution, submission_evidence}, where evidence is accepted or retired",
                    "job metadata fields are optional for reference-only retries; retry never recompiles, renews the deadline or reads the record, avoiding a get expiry race; execution.get and execution.result separately retrieve records under their own contracts",
                    "after output or the record is forgotten, guarded retries return submission_evidence=retired and the original execution reference without job metadata or output; never redispatch",
                    "max_records and max_records_per_account bound shared logical entries including Preparing reservations and retired tombstones; a record and its alias are charged once, with no separate retry-history configuration",
                ],
            );
        }
        descriptors.push(descriptor);
    }
    for (id, kind, visibility, step_up) in [
        (
            ACTION_RUNTIME_SUBMISSION_LOOKUP,
            ActionKind::View,
            VisibilityTier::ManagementState,
            false,
        ),
        (
            ACTION_RUNTIME_EXECUTION_GET,
            ActionKind::View,
            VisibilityTier::ManagementState,
            false,
        ),
        (
            ACTION_RUNTIME_EXECUTION_LIST,
            ActionKind::View,
            VisibilityTier::ManagementState,
            false,
        ),
        (
            ACTION_RUNTIME_EXECUTION_RESULT,
            ActionKind::View,
            VisibilityTier::ProtectedPayload,
            true,
        ),
        (
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
            ActionKind::View,
            VisibilityTier::ProtectedPayload,
            true,
        ),
        (
            ACTION_RUNTIME_EXECUTION_CANCEL,
            ActionKind::Mutation,
            VisibilityTier::ManagementState,
            true,
        ),
        (
            ACTION_RUNTIME_EXECUTION_FORGET,
            ActionKind::Mutation,
            VisibilityTier::ManagementState,
            false,
        ),
    ] {
        let fields = if id == ACTION_RUNTIME_SUBMISSION_LOOKUP {
            vec![field("submission_identity", "submission_identity", true)]
        } else if id == ACTION_RUNTIME_EXECUTION_LIST {
            vec![
                field("limit", "positive_usize", false),
                field("cursor", "string", false),
                field("max_bytes", "positive_usize", false),
            ]
        } else if id == ACTION_RUNTIME_EXECUTION_OUTPUT_READ {
            vec![
                field("execution_id", "string", true),
                field("cursor", "u64", false),
                field("limit", "positive_usize", false),
                field("max_bytes", "positive_usize", false),
                field("wait_ms", "u64", false),
            ]
        } else {
            vec![field("execution_id", "string", true)]
        };
        let output_fields = match id {
            ACTION_RUNTIME_SUBMISSION_LOOKUP => vec![
                field("evidence", "unproven|preparing|accepted|retired", true),
                field("execution", "execution_reference|null", true),
            ],
            ACTION_RUNTIME_EXECUTION_LIST => vec![
                field("entries", "list<execution_record>", true),
                field("next_cursor", "string|null", true),
            ],
            ACTION_RUNTIME_EXECUTION_RESULT => vec![
                field("record", "execution_record", true),
                field("output", "value", true),
                field("retention_failure", "value", true),
                field("unresolved_operations", "unresolved_operations|null", true),
            ],
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ => vec![
                field("entries", "list<runtime_output_event>", true),
                field("next_cursor", "u64", true),
                field("last_sequence", "u64", true),
                field("has_more", "bool", true),
                field("complete", "bool", true),
            ],
            ACTION_RUNTIME_EXECUTION_FORGET => vec![field("forgotten", "bool", true)],
            _ => execution_record_fields(),
        };
        let output = if id == ACTION_RUNTIME_EXECUTION_FORGET {
            schema(&format!("{id}.output"), "map", output_fields, vec![])
        } else if id == ACTION_RUNTIME_SUBMISSION_LOOKUP {
            let mut output = schema(
                &format!("{id}.output"),
                "map",
                output_fields,
                vec![
                    "read-only volatile acceptance evidence; no job payload or retained output is returned",
                ],
            );
            output.definitions.push(execution_reference_schema());
            output
        } else {
            execution_output_schema(
                &format!("{id}.output"),
                output_fields,
                vec![
                    "body outcome, retained result availability and cleanup are separate observations",
                    "Stream output is an execution-owned, bounded, cursor-readable log for the current host lifecycle",
                ],
            )
        };
        let mut input_notes = vec![
            "only the owning account instance can access a record; account recreation never inherits ownership",
        ];
        match id {
            ACTION_RUNTIME_SUBMISSION_LOOKUP => input_notes.extend([
                "read-only lookup returns no payload or output and never dispatches; execution is null for unproven or preparing, and the original reference for accepted or retired",
                "preparing is not accepted; unproven is not negative effect proof, including absent identities in closed ranges",
                "retained aliases in old retry ranges remain queryable; closed absent identities never execute; only the trusted host can close a retry range, with no client close action",
            ]),
            ACTION_RUNTIME_EXECUTION_RESULT => input_notes.push(
                "result additionally requires current authority for all admitted operations/identities, MFA, scope, justification and ttl_ms",
            ),
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ => input_notes.extend([
                "output.read has the same visibility gate and rechecks session and current authority after any wait; cursor is the last delivered sequence, starting at zero",
                "max_bytes is capped by executions.max_output_page_bytes independently of the State/Fact query page limit",
            ]),
            ACTION_RUNTIME_EXECUTION_CANCEL => {
                input_notes.push("cancel does not roll back effects")
            }
            ACTION_RUNTIME_EXECUTION_FORGET => input_notes.push(
                "active records and child receipts with an active source cannot be forgotten",
            ),
            ACTION_RUNTIME_EXECUTION_LIST => input_notes.push(
                "list cursors are scoped to this host and account instance",
            ),
            _ => {}
        }
        let mut descriptor = action(
            id,
            "runtime",
            kind,
            ActionPolicy::new(RiskLevel::Elevated, visibility, step_up),
            vec![],
            schema(&format!("{id}.input"), "map", fields, input_notes),
            output,
        );
        if id == ACTION_RUNTIME_SUBMISSION_LOOKUP {
            descriptor
                .input
                .definitions
                .push(submission_identity_schema());
        }
        descriptors.push(descriptor);
    }
    descriptors
}

fn submission_identity_schema() -> SchemaDescriptor {
    schema(
        "submission_identity",
        "map",
        vec![
            field("registry_instance", "string", true),
            semantic_field("retry_epoch", "string", true, "canonical_unsigned_decimal"),
            field("nonce", "string", true),
        ],
        vec![
            "retry_epoch is a canonical unsigned u64 decimal STRING: 0 or nonzero digits without leading zeros; integers, signs, whitespace and overflow are rejected",
            "scope is registry instance plus retry range, not SID; identity conveys no authority, and host restart changes registry_instance",
            "immutable account ownership applies across session refresh; account recreation cannot inherit evidence",
        ],
    )
}

fn submission_retry_scope_schema() -> SchemaDescriptor {
    schema(
        "submission_retry_scope",
        "map",
        vec![
            field("registry_instance", "string", true),
            semantic_field("retry_epoch", "string", true, "canonical_unsigned_decimal"),
        ],
        vec![
            "retry_epoch is a canonical unsigned u64 decimal string, not an integer; the scope identifies the live registry and its currently open retry range, not authority",
            "only the trusted host closes a retry range; restart changes registry_instance and old-instance identities are rejected",
        ],
    )
}

fn runtime_description_schema() -> SchemaDescriptor {
    let mut output = schema(
        "runtime.describe.output",
        "map",
        vec![
            field("config", "map", true),
            field("subscription_limits", "map", true),
            field("source_version", "u64", true),
            field("execution_modes", "list<execution_mode>", true),
            field("supported_imports", "list<string>", true),
            field("atomic", "bool", true),
            field("modules", "list<value>", true),
            field("submission_retry_scope", "submission_retry_scope", true),
        ],
        vec![
            "config omits host capability selectors; exposure is an additional ceiling and never grants the caller authority",
            "modules contains complete canonical manifests visible under current host exposure and caller capabilities, including every transitive dependency; it is advisory and does not confer execution authority",
        ],
    );
    output.definitions.push(submission_retry_scope_schema());
    output.definitions.push(schema(
        "execution_mode",
        "map",
        vec![
            field("mode", "string", true),
            field("lifetime", "string", true),
            field("owner", "string", true),
            field("enabled", "bool", true),
            field("accepting", "bool", true),
            field("entries", "list<string>", true),
            field("output_modes", "list<string>", true),
        ],
        vec![
            "each (mode, lifetime) pair is unique; use the pair, not list position, to select a contract",
            "calls, subscriptions and submissions use host lifetime with distinct ownership",
            "disabled contracts remain discoverable; enabled reflects this build and host configuration",
            "accepting additionally reflects submission shutdown; it does not reserve capacity or confer authority",
            "output_modes applies only to this row and remains subject to installed method contracts and collection limits",
        ],
    ));
    output
}

pub(super) fn execution_budget_schema() -> SchemaDescriptor {
    schema(
        "execution_budget",
        "map",
        vec![
            field("max_micro_usd", "decimal_u64|null", false),
            field("max_inflight_ops", "u32|null", false),
            field("max_inference_tokens", "decimal_u64|null", false),
        ],
        vec![
            "process-tree limits shared by the execution and its descendants; no calendar reset",
            "omitted or null dimensions add no restriction; the host and ancestor ceilings still apply",
            "zero is a real limit; cost and token outputs use exact decimal strings",
            "limits bound reservation estimates; measured usage settles afterward and may exceed estimates",
            "outputs report the admitted tree ceiling, not remaining quota; children share their source budget and recovery or ancestor ceilings can be tighter",
        ],
    )
}

fn execution_record_fields() -> Vec<FieldDescriptor> {
    vec![
        field("execution_id", "string", true),
        field("execution", "execution_reference", true),
        field("budget", "execution_budget", true),
        field("source", "execution_source|null", true),
        field("lifetime", "string", true),
        field("status", "string", true),
        field("outcome", "string|null", true),
        field("result_status", "string", true),
        field("unresolved_operation_count", "i64|null", true),
        field("unresolved_identities_incomplete", "bool|null", true),
        field("cleanup_status", "string", true),
        field("stop_reason", "string|null", false),
        field("created_at", "i64", true),
        field("deadline", "i64", true),
        field("finished_at", "i64|null", true),
        field("expires_at", "i64|null", true),
    ]
}

fn execution_output_schema(
    id: &str,
    fields: Vec<FieldDescriptor>,
    notes: Vec<&str>,
) -> SchemaDescriptor {
    let mut output = schema(id, "map", fields, notes);
    output.definitions = vec![
        execution_budget_schema(),
        unresolved_operations_schema(),
        runtime_output_event_schema(),
        schema(
            "execution_record",
            "map",
            execution_record_fields(),
            vec![
                "source is null for direct submissions; child receipts retain their source while it is active, even after their result expires",
            ],
        ),
        execution_reference_schema(),
        schema(
            "execution_source",
            "map",
            vec![
                field("execution_id", "string", true),
                field("operation_id", "string", true),
            ],
            vec![
                "execution_id identifies the parent; operation_id is process/execution/invocation/position/attempt as canonical unsigned decimal coordinates",
                "same-source acceptance reconciliation is in memory; distinct invocations and explicit attempts are independent; root submissions share acceptance only with an explicit submission_identity",
            ],
        ),
    ];
    output
}

fn execution_reference_schema() -> SchemaDescriptor {
    schema(
        "execution_reference",
        "map",
        vec![
            field("execution_id", "string", true),
            field("process_id", "decimal_u64", true),
            field("program_id", "string", true),
        ],
        vec![
            "program_id identifies the originating program; an execution reference does not confer authority",
        ],
    )
}

pub(super) fn unresolved_operations_schema() -> SchemaDescriptor {
    schema(
        "unresolved_operations",
        "map",
        vec![
            field("operation_ids", "list<string>", true),
            field("identities_incomplete", "bool", true),
        ],
        vec![
            "host-observed IDs requiring external reconciliation; success does not imply an empty set",
            "identities_incomplete means some IDs exceeded the bounded retention allowance",
        ],
    )
}

fn runtime_output_event_schema() -> SchemaDescriptor {
    let mut event = schema(
        "runtime_output_event",
        "map",
        vec![],
        vec!["retained Stream events are ordered by execution-owned sequence"],
    );
    event.discriminator = Some("kind".into());
    for (kind, specific) in [
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
                field("failure", "value|null", true),
                field("taint", "value", true),
                field("origin", "string", true),
            ],
        ),
        (
            "terminal",
            vec![
                field("outcome", "string", true),
                field("result_status", "string", true),
                field("unresolved_operation_count", "i64", true),
                field("unresolved_identities_incomplete", "bool", true),
                field("last_output_sequence", "i64", true),
            ],
        ),
    ] {
        let id = format!("runtime_output_event.{kind}");
        event.variants.insert(kind.into(), id.clone());
        let mut fields = vec![
            field("execution_id", "string", true),
            field("sequence", "i64", true),
            field("kind", "string", true),
        ];
        fields.extend(specific);
        event.definitions.push(schema(&id, "map", fields, vec![]));
    }
    event
}

fn protocol_greeting_fields() -> Vec<FieldDescriptor> {
    vec![
        field("protocol_version", "u64", true),
        field("server_name", "string", true),
        field("encoding", "string", true),
        field("server_rev", "u64", true),
        field("registry_rev", "u64", true),
        field("server_time_ms", "u64", true),
    ]
}

fn registry_snapshot_fields() -> Vec<FieldDescriptor> {
    let mut fields = protocol_greeting_fields();
    fields.extend([
        field("root_data_authority", "map", true),
        field("actions", "list<action_descriptor>", true),
        field("streams", "list<stream_descriptor>", true),
        field("visibility_tiers", "list<string>", true),
        field("secret_classes", "list<string>", true),
    ]);
    fields
}

fn build_action_descriptors() -> Vec<ActionDescriptor> {
    vec![
        action(
            ACTION_PROTOCOL_DESCRIBE,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema(
                "protocol.greeting",
                "map",
                protocol_greeting_fields(),
                vec![
                    "compact service negotiation and revisions; the catalog is fetched with protocol.registry.snapshot, while transport metadata belongs to the active adapter",
                ],
            ),
        ),
        action(
            ACTION_PROTOCOL_REGISTRY_SNAPSHOT,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema(
                "protocol.registry_snapshot",
                "map",
                registry_snapshot_fields(),
                vec!["complete action and stream catalog with protocol greeting fields"],
            ),
        ),
        action(
            ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema(
                "protocol.action_descriptor_get.input",
                "map",
                vec![field("action", "string", true)],
                vec!["returns an action descriptor for the supplied action id"],
            ),
            schema("protocol.action_descriptor", "map", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_TYPE_LIST,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema("resource.type_list.input", "null", vec![], vec![]),
            schema("resource.type_list.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_TYPE_DESCRIBE,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "resource.type_describe.input",
                "map",
                vec![semantic_field(
                    "resource_type",
                    "string",
                    true,
                    "resource_ref",
                )],
                vec!["returns semantic edit metadata for one resource type"],
            ),
            schema("resource.type_descriptor.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_VIEW_DESCRIBE,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "resource.view_describe.input",
                "map",
                vec![semantic_field("view", "string", true, "resource_ref")],
                vec!["returns query/projection metadata for one fixed resource view"],
            ),
            schema("resource.view_descriptor.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.principal_effective.input",
                "null",
                vec![],
                vec![],
            ),
            {
                let mut output = schema(
                    "authority.principal_effective.output",
                    "map",
                    vec![
                        field("username", "string", true),
                        field("identity_path", "path", true),
                        field("authentication", "authentication_evidence", true),
                        field("mfa_level", "u8", true),
                        field("grant_count", "usize", true),
                        field("grants", "list<string>", true),
                        field("root_data_authority", "map", true),
                    ],
                    vec![
                        "mfa_level is derived from authentication and does not enlarge resource grants",
                    ],
                );
                output.definitions.push(authentication_evidence_schema());
                output
            },
        ),
        action(
            ACTION_AUTHORITY_ACTION_MATRIX,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.action_matrix.input",
                "map",
                vec![field("domain", "string", false)],
                vec![
                    "explains current principal only",
                    "template coverage is advisory and never grants or denies a concrete invocation",
                    "uncovered templates require concrete input; narrow grants and optional sections may still authorize a call",
                ],
            ),
            {
                let mut output = schema(
                    "authority.action_matrix.output",
                    "list<authority_hint>",
                    vec![],
                    vec![],
                );
                output
                    .definitions
                    .push(authority_hint_schema("authority_hint"));
                output
            },
        ),
        action(
            ACTION_AUTHORITY_RESOURCE_ACCESS,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.resource_access.input",
                "map",
                vec![field("target", "path", true), field("verb", "string", true)],
                vec!["single-resource explanation; broad scans must use a paged/artifact action"],
            ),
            schema("authority.resource_access.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_ACTION_EXPLAIN,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.action.explain.input",
                "map",
                vec![field("action", "string", true)],
                vec![
                    "explains known action gates for the current principal; concrete authority still requires action input",
                ],
            ),
            authority_hint_schema("authority.action.explain.output"),
        ),
        action(
            ACTION_VISIBILITY_AUTHORITY_DESCRIBE,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("visibility.authority.input", "null", vec![], vec![]),
            schema("visibility.authority.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_STATE_READ,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::BusinessData, true),
            vec![authority("read", "state://**")],
            schema(
                "visibility.state_read.input",
                "map",
                vec![field("path", "path", true)],
                vec![
                    "rejects state://vault/**; use secret.*",
                    "requires ActionCall.scope, justification, and ttl_ms",
                ],
            ),
            schema("visibility.state_read.output", "value", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_STATE_LIST,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::BusinessData, true),
            vec![authority("read", "state://**")],
            schema(
                "visibility.state_list.input",
                "map",
                vec![field("prefix", "path", true)],
                vec![
                    "rejects state://vault/**; use secret.*",
                    "requires ActionCall.scope, justification, and ttl_ms",
                ],
            ),
            schema("visibility.state_list.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_SECRET_CATALOG,
            "secret",
            ActionKind::Secret,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::SecretMetadata, false),
            vec![],
            schema("secret.catalog.input", "map", vec![], vec![]),
            schema("secret.catalog.output", "value", vec![], vec![]),
        ),
        action(
            ACTION_STATE_SNAPSHOT,
            "state",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, false),
            vec![
                authority("read", "state://kernel/**"),
                authority("perform", crate::paths::PROCESS_INSPECT_EFFECT),
                authority("read", "state://fact/**"),
            ],
            schema(
                "state.snapshot.input",
                "map",
                vec![FieldDescriptor {
                    max_items: Some(MAX_SNAPSHOT_SECTIONS),
                    ..field("sections", "list<snapshot_section>", false)
                }],
                vec![
                    "runtime.include_recent_facts defaults to false",
                    "a snapshot accepts at most 16 sections and at most one runtime section",
                    "default sections are sessions and runtime; kernel_config sections require an explicit manageable prefix",
                    "all sections accept limit, cursor and max_bytes and return pages; truncated lists section keys with continuations",
                    "snapshots are full live observations; server_rev is a fact cursor, not a transactional state revision",
                    "runtime.include_recent_facts=true requires ActionCall.scope, justification, and ttl_ms",
                    "runtime.process optionally selects one process; runtime.include_recent_facts=true requires an explicit process and read authority for its state://fact path",
                    "runtime recent_facts uses the bounded audit fact-page shape; fact_cursor is a decimal u64 string",
                ],
            ),
            schema("state.snapshot.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_READ,
            "config",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema(
                "config.read.input",
                "map",
                vec![field("path", "path", true)],
                vec![],
            ),
            schema("config.read.output", "value", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_LIST,
            "config",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema(
                "config.list.input",
                "map",
                vec![field("prefix", "path", true)],
                vec![],
            ),
            schema("config.list.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_WRITE_CAS,
            "config",
            ActionKind::Mutation,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true),
            vec![authority("write", "state://kernel/**")],
            schema(
                "config.write_cas.input",
                "map",
                vec![
                    field("path", "path", true),
                    field("value", "value", true),
                    field("expected_version", "u64|null", false),
                ],
                vec![
                    "requires MFA step-up",
                    "management paths with dedicated actions must use their dedicated action family",
                ],
            ),
            schema("protocol.empty", "null", vec![], vec![]),
        ),
        access_action(
            ACTION_ACCESS_USER_READ,
            ActionKind::View,
            false,
            vec![field("username", "string", true)],
        ),
        access_action(ACTION_ACCESS_USER_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_USER_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("username", "string", true),
                field("value", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_USER_DISABLE,
            ActionKind::Mutation,
            true,
            vec![
                field("username", "string", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_ROLE_READ,
            ActionKind::View,
            false,
            vec![field("role", "string", true)],
        ),
        access_action(ACTION_ACCESS_ROLE_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_ROLE_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("role", "string", true),
                field("value", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_SESSION_CURRENT_LOGOUT,
            ActionKind::Mutation,
            false,
            vec![],
        ),
        access_action(ACTION_ACCESS_SESSION_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_SESSION_REVOKE,
            ActionKind::Mutation,
            true,
            vec![field("sid", "string", true)],
        ),
        access_action(
            ACTION_ACCESS_SESSION_REVOKE_USER,
            ActionKind::Mutation,
            true,
            vec![field("username", "string", true)],
        ),
        action(
            ACTION_RUNTIME_PROCESS_INSPECT,
            "runtime",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, false),
            vec![authority("perform", crate::paths::PROCESS_INSPECT_EFFECT)],
            schema(
                "runtime.process_inspect.input",
                "map",
                vec![
                    field("process", "decimal_u64", false),
                    field("include_recent_facts", "bool", false),
                    field("limit", "positive_usize", false),
                    field("cursor", "decimal_u64", false),
                    field("max_bytes", "positive_usize", false),
                    field("fact_limit", "positive_usize", false),
                ],
                vec![
                    "metadata requires only perform authority for effect://kernel/process/inspect, as in a runtime snapshot section",
                    "include_recent_facts defaults to false; true requires an explicit process, fact read authority, MFA level 2, scope, justification and ttl_ms",
                    "limit bounds process rows in ascending ID order; continue with cursor=next_cursor",
                    "process and cursor are mutually exclusive; fact_limit only applies when include_recent_facts=true",
                ],
            ),
            schema(
                "runtime.process_inspect.output",
                "map",
                vec![
                    field("entries", "list<process_summary>", true),
                    field("next_cursor", "decimal_u64|null", true),
                ],
                vec![
                    "process, identity and parent IDs are decimal u64 strings; child_count avoids materializing an unbounded tree",
                    "recent_facts is a bounded fact page when requested; no all-history fact_count is computed",
                ],
            ),
        ),
        action(
            ACTION_AUDIT_FACTS_RECENT,
            "audit",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "audit.facts_recent.input",
                "map",
                vec![
                    field("process", "decimal_u64", false),
                    field("from", "decimal_u64", false),
                    field("before", "decimal_u64", false),
                    field("limit", "positive_usize", false),
                    field("max_bytes", "positive_usize", false),
                    field("max_examined", "positive_usize", false),
                ],
                vec![
                    "newest append slots first; continue with before=next and the same from/filter",
                ],
            ),
            fact_page_schema("audit.facts_recent.output"),
        ),
        action(
            ACTION_LINEAGE_TRACE_READ,
            "lineage",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "lineage.trace_read.input",
                "map",
                vec![
                    field("process", "decimal_u64", true),
                    field("from", "decimal_u64", false),
                    field("before", "decimal_u64", false),
                    field("limit", "positive_usize", false),
                    field("max_bytes", "positive_usize", false),
                    field("max_examined", "positive_usize", false),
                ],
                vec![
                    "from is a global append slot, not an ordinal within a process; oldest slots first",
                    "continue with from=next and before=end using the same filter",
                    "partial/partial_reason describe omitted lineage projections independently of page completion",
                ],
            ),
            fact_page_schema("lineage.trace_read.output"),
        ),
        action(
            ACTION_LINEAGE_FACT_READ,
            "lineage",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "lineage.fact_read.input",
                "map",
                vec![
                    field("op_id", "operation_id", true),
                    field("process", "decimal_u64", false),
                    field("max_bytes", "positive_usize", false),
                ],
                vec![
                    "requires ActionCall.scope, justification, and ttl_ms",
                    "process defaults to the process in op_id and requires read authority for state://fact/<process>",
                    "only a record whose current caller matches process is visible; missing or nonmatching records are reported as unknown",
                ],
            ),
            schema(
                "lineage.fact_read.output",
                "map",
                vec![],
                vec![
                    "output includes partial/partial_reason when lineage projections are not fully materialized",
                    "indexed lookup filters the current caller before enforcing the record byte budget or copying/decoding; an oversized matching record fails the read",
                ],
            ),
        ),
        action(
            ACTION_HEALTH_SUMMARY,
            "health",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema("health.summary.input", "null", vec![], vec![]),
            schema(
                "health.summary.output",
                "map",
                vec![],
                vec![
                    "fact_sample contains sampled_facts and decisions for one bounded reverse page with from/next/end/order/complete/examined/encoded_bytes",
                    "fact_sample and fact_cursor are null when observation storage is not installed",
                    "sample counts describe only that page; no all-history fact_count or fact_decisions is computed",
                    "fact_cursor is a decimal u64 append-head string, not an outcome-update revision",
                    "process_count reports retained process records in constant time; use runtime.process.inspect for bounded status pages",
                ],
            ),
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_LIST,
            ActionKind::View,
            false,
            vec![],
        ),
        source_claim_inspect_descriptor(),
        source_event_decision_inspect_descriptor(),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_READ,
            ActionKind::View,
            false,
            vec![field("id", "string", true)],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            ActionKind::Mutation,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
                field("expected_installation_epoch", "u64|null", false),
            ],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_UPDATE,
            ActionKind::Mutation,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
                field("expected_installation_epoch", "u64|null", false),
            ],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
            ActionKind::Mutation,
            true,
            vec![
                field("id", "string", true),
                field("expected_version", "u64", true),
                field("expected_installation_epoch", "u64", true),
            ],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_START,
            ActionKind::Mutation,
            true,
            vec![field("id", "string", true)],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_STOP,
            ActionKind::Mutation,
            true,
            vec![field("id", "string", true)],
        ),
        external_action(
            ACTION_EXTERNAL_INSTALLATION_REVOKE,
            ActionKind::Mutation,
            true,
            vec![
                field("installation_id", "string", true),
                field("credential_generation_floor", "u64", false),
            ],
        ),
        external_action(
            ACTION_EXTERNAL_MANIFEST_LIST,
            ActionKind::View,
            false,
            vec![],
        ),
        external_action(
            ACTION_EXTERNAL_MANIFEST_READ,
            ActionKind::View,
            false,
            vec![field("platform", "string", true)],
        ),
        external_action(
            ACTION_EXTERNAL_MANIFEST_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("platform", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        projection_status_action(
            ACTION_PROJECTION_IN_PROCESS_STATUS_LIST,
            ActionKind::View,
            false,
            vec![],
        ),
        projection_status_action(
            ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
            ActionKind::View,
            false,
            vec![field("id", "string", true)],
        ),
        inference_action(
            ACTION_INFERENCE_BACKEND_LIST,
            ActionKind::View,
            false,
            vec![],
        ),
        inference_action(
            ACTION_INFERENCE_BACKEND_READ,
            ActionKind::View,
            false,
            vec![field("id", "string", true)],
        ),
        inference_action(
            ACTION_INFERENCE_BACKEND_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        inference_action(ACTION_INFERENCE_MODEL_LIST, ActionKind::View, false, vec![]),
        inference_action(
            ACTION_INFERENCE_MODEL_READ,
            ActionKind::View,
            false,
            vec![field("id", "string", true)],
        ),
        inference_action(
            ACTION_INFERENCE_MODEL_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        inference_action(ACTION_INFERENCE_GROUP_LIST, ActionKind::View, false, vec![]),
        inference_action(
            ACTION_INFERENCE_GROUP_READ,
            ActionKind::View,
            false,
            vec![field("name", "string", true)],
        ),
        inference_action(
            ACTION_INFERENCE_GROUP_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("name", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        inference_action(
            ACTION_INFERENCE_ROUTING_READ,
            ActionKind::View,
            false,
            vec![],
        ),
        inference_action(
            ACTION_INFERENCE_ROUTING_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_CREATE,
            vec![
                field("pairing_id", "string", true),
                field("installation_id", "string", true),
                field("allowed_roles", "list<string>", false),
                field("expires_at", "u64", false),
                field("reveal_display_secret", "bool", false),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_APPROVE,
            vec![
                field("pairing_id", "string", true),
                field("approved_roles", "list<string>", true),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_DENY,
            vec![field("pairing_id", "string", true)],
        ),
    ]
}

#[derive(Clone)]
struct ActionPolicy {
    risk: RiskLevel,
    visibility: VisibilityTier,
    requires_step_up: bool,
}

impl ActionPolicy {
    const fn new(risk: RiskLevel, visibility: VisibilityTier, requires_step_up: bool) -> Self {
        Self {
            risk,
            visibility,
            requires_step_up,
        }
    }
}

fn access_action(
    id: &str,
    kind: ActionKind,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    let authority_templates = access_authority(id, &kind);
    action(
        id,
        "access",
        kind,
        ActionPolicy::new(
            if requires_step_up {
                RiskLevel::Elevated
            } else {
                RiskLevel::Low
            },
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        authority_templates,
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn access_authority(id: &str, kind: &ActionKind) -> Vec<AuthorityTemplate> {
    let user_mgmt = authority("perform", crate::paths::MANAGE_USERS_EFFECT);
    match id {
        ACTION_ACCESS_SESSION_CURRENT_LOGOUT => vec![],
        ACTION_ACCESS_USER_READ | ACTION_ACCESS_USER_LIST => {
            vec![authority("read", crate::paths::USERS_AUTHORITY), user_mgmt]
        }
        ACTION_ACCESS_USER_WRITE_CAS | ACTION_ACCESS_USER_DISABLE => {
            vec![authority("write", crate::paths::USERS_AUTHORITY), user_mgmt]
        }
        ACTION_ACCESS_ROLE_READ | ACTION_ACCESS_ROLE_LIST => {
            vec![authority("read", crate::paths::ROLES_AUTHORITY), user_mgmt]
        }
        ACTION_ACCESS_ROLE_WRITE_CAS => {
            vec![authority("write", crate::paths::ROLES_AUTHORITY), user_mgmt]
        }
        ACTION_ACCESS_SESSION_LIST => {
            vec![
                authority("read", crate::paths::SESSIONS_AUTHORITY),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_SESSION_REVOKE => {
            vec![
                authority("write", crate::paths::SESSIONS_AUTHORITY),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_SESSION_REVOKE_USER => {
            vec![authority("write", crate::paths::USERS_AUTHORITY), user_mgmt]
        }
        _ if matches!(kind, ActionKind::Mutation) => {
            vec![
                authority("write", crate::paths::CONSOLE_AUTHORITY),
                user_mgmt,
            ]
        }
        _ => vec![
            authority("read", crate::paths::CONSOLE_AUTHORITY),
            user_mgmt,
        ],
    }
}

fn external_action(
    id: &str,
    kind: ActionKind,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    let authority_templates = external_authority(id);
    action(
        id,
        "external",
        kind,
        ActionPolicy::new(
            if requires_step_up {
                RiskLevel::Elevated
            } else {
                RiskLevel::Low
            },
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        authority_templates,
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn source_claim_inspect_descriptor() -> ActionDescriptor {
    action(
        ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT,
        "external",
        ActionKind::View,
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true),
        vec![authority(
            "perform",
            "effect://external/source/*/*/claims/inspect",
        )],
        schema(
            "external.source.claim.inspect.input",
            "map",
            vec![
                field("installation_id", "string", true),
                field("projection_id", "string", true),
                field("scope_epoch", "decimal_u64", true),
                field("stream_epoch", "decimal_u64", false),
                field("event_id", "string", true),
                field("claim_id", "string", true),
            ],
            vec![
                "requires a host-installed SourceClaimInspection facet; unavailable hosts reject without inferring evidence",
                "installation_id, projection_id and event_id are literal identity segments of at most 256 bytes",
                "stream_epoch is required for an ordered event and absent for an unordered event; it distinguishes successive incarnations of one stream ID",
                "claim_id is the 32 lowercase hexadecimal digits from a trusted host indeterminate-commit log; Source ACKs do not disclose it and this action does not enumerate claims",
                "requires ActionCall.justification of 1..=1024 bytes and concrete perform authority for effect://external/source/{installation_id}/{projection_id}/claims/inspect",
                "operator and inspection time come from the authenticated host; evidence is returned only after private inspection audit commits",
            ],
        ),
        source_inspection_output_schema("external.source.claim.inspect.output"),
    )
}

fn source_event_decision_inspect_descriptor() -> ActionDescriptor {
    action(
        ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT,
        "external",
        ActionKind::View,
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true),
        vec![authority(
            "perform",
            "effect://external/source/*/*/events/inspect",
        )],
        schema(
            "external.source.event.decision.inspect.input",
            "map",
            vec![
                field("installation_id", "string", true),
                field("projection_id", "string", true),
                field("scope_epoch", "decimal_u64", true),
                field("stream_epoch", "decimal_u64", false),
                field("event_id", "string", true),
            ],
            vec![
                "requires a host-installed SourceClaimInspection facet; unavailable hosts reject without inferring evidence",
                "stream_epoch is required for an ordered event and absent for an unordered event; returns only the retained decision for that exact identity",
                "the action does not enumerate events or claims",
                "if the same event ID is accepted again after its prior decision expires, only the current decision is returned; old attempts are not identifiable",
                "absence may mean expiry or cleanup and does not prove rollback or authorize replay",
                "requires ActionCall.justification of 1..=1024 bytes, MFA level 2, and concrete perform authority for effect://external/source/{installation_id}/{projection_id}/events/inspect",
                "operator and inspection time come from the authenticated host; evidence is returned only after private inspection audit commits",
            ],
        ),
        source_inspection_output_schema("external.source.event.decision.inspect.output"),
    )
}

fn source_inspection_output_schema(id: &str) -> SchemaDescriptor {
    let mut output = schema(
        id,
        "map",
        vec![],
        vec![
            "unproven is absence of retained evidence, never proof of rollback or permission to replay",
            "no Source commit, sink mutation, maintenance, or event deletion is performed",
        ],
    );
    output.discriminator = Some("status".into());
    for (status, fields) in [
        (
            "committed",
            vec![field("receipt", "source_claim_receipt", true)],
        ),
        ("unproven", vec![]),
    ] {
        let id = format!("source_claim_evidence.{status}");
        output.variants.insert(status.into(), id.clone());
        output.definitions.push(schema(
            &id,
            "map",
            [field("status", "string", true)]
                .into_iter()
                .chain(fields)
                .collect(),
            vec![],
        ));
    }
    output.definitions.push(schema(
        "source_claim_receipt",
        "map",
        vec![
            field("installation_id", "string", true),
            field("projection_id", "string", true),
            field("scope_epoch", "decimal_u64", true),
            field("stream_epoch", "decimal_u64", false),
            field("event_id", "string", true),
            field("claim_id", "string", true),
            field("sink", "path", true),
            field("received_at_ms", "i64", true),
        ],
        vec!["stream_epoch is null for unordered events and a positive decimal u64 for ordered events; claim_id uses 32 lowercase hexadecimal digits; no event payload is disclosed"],
    ));
    output
}

fn external_authority(id: &str) -> Vec<AuthorityTemplate> {
    match id {
        ACTION_EXTERNAL_INSTALLATION_LIST | ACTION_EXTERNAL_INSTALLATION_READ => {
            vec![authority(
                "read",
                crate::paths::EXTERNAL_INSTALLATIONS_AUTHORITY,
            )]
        }
        ACTION_EXTERNAL_INSTALLATION_INSTALL
        | ACTION_EXTERNAL_INSTALLATION_UPDATE
        | ACTION_EXTERNAL_INSTALLATION_UNINSTALL => {
            vec![authority(
                "write",
                crate::paths::EXTERNAL_INSTALLATIONS_AUTHORITY,
            )]
        }
        ACTION_EXTERNAL_INSTALLATION_START => vec![
            authority("read", crate::paths::EXTERNAL_INSTALLATIONS_AUTHORITY),
            authority("perform", crate::paths::PROCESS_SPAWN_EFFECT),
        ],
        ACTION_EXTERNAL_INSTALLATION_STOP => {
            vec![authority("perform", crate::paths::PROCESS_KILL_EFFECT)]
        }
        ACTION_EXTERNAL_INSTALLATION_REVOKE => vec![
            authority("read", crate::paths::EXTERNAL_INSTALLATIONS_AUTHORITY),
            authority("perform", crate::paths::EXTERNAL_REVOKE_EFFECT),
        ],
        ACTION_EXTERNAL_MANIFEST_LIST | ACTION_EXTERNAL_MANIFEST_READ => {
            vec![authority("read", crate::paths::MANIFESTS_AUTHORITY)]
        }
        ACTION_EXTERNAL_MANIFEST_WRITE_CAS => {
            vec![authority("write", crate::paths::MANIFESTS_AUTHORITY)]
        }
        _ => vec![authority(
            "read",
            crate::paths::EXTERNAL_INSTALLATIONS_AUTHORITY,
        )],
    }
}

fn projection_status_action(
    id: &str,
    kind: ActionKind,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    action(
        id,
        "projection",
        kind,
        ActionPolicy::new(
            if requires_step_up {
                RiskLevel::Elevated
            } else {
                RiskLevel::Low
            },
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        vec![authority("read", crate::paths::PROJECTION_STATUS_AUTHORITY)],
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn inference_action(
    id: &str,
    kind: ActionKind,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    action(
        id,
        "inference",
        kind,
        ActionPolicy::new(
            if requires_step_up {
                RiskLevel::Elevated
            } else {
                RiskLevel::Low
            },
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        inference_authority(id),
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn inference_authority(id: &str) -> Vec<AuthorityTemplate> {
    let (verb, target) = match id {
        ACTION_INFERENCE_BACKEND_LIST | ACTION_INFERENCE_BACKEND_READ => {
            ("read", crate::paths::INFERENCE_BACKENDS_AUTHORITY)
        }
        ACTION_INFERENCE_BACKEND_WRITE_CAS => ("write", crate::paths::INFERENCE_BACKENDS_AUTHORITY),
        ACTION_INFERENCE_MODEL_LIST | ACTION_INFERENCE_MODEL_READ => {
            ("read", crate::paths::INFERENCE_MODELS_AUTHORITY)
        }
        ACTION_INFERENCE_MODEL_WRITE_CAS => ("write", crate::paths::INFERENCE_MODELS_AUTHORITY),
        ACTION_INFERENCE_GROUP_LIST | ACTION_INFERENCE_GROUP_READ => {
            ("read", crate::paths::INFERENCE_GROUPS_AUTHORITY)
        }
        ACTION_INFERENCE_GROUP_WRITE_CAS => ("write", crate::paths::INFERENCE_GROUPS_AUTHORITY),
        ACTION_INFERENCE_ROUTING_READ => ("read", crate::paths::INFERENCE_ROUTING_PATH),
        ACTION_INFERENCE_ROUTING_WRITE_CAS => ("write", crate::paths::INFERENCE_ROUTING_PATH),
        _ => ("read", crate::paths::INFERENCE_AUTHORITY),
    };
    vec![authority(verb, target)]
}

fn pairing_action(id: &str, fields: Vec<FieldDescriptor>) -> ActionDescriptor {
    action(
        id,
        "pairing",
        ActionKind::Mutation,
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true),
        pairing_authority(id),
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn pairing_authority(id: &str) -> Vec<AuthorityTemplate> {
    let target = match id {
        ACTION_PAIRING_CREATE => crate::paths::PAIRING_CREATE_EFFECT,
        ACTION_PAIRING_APPROVE => crate::paths::PAIRING_APPROVE_EFFECT,
        ACTION_PAIRING_DENY => crate::paths::PAIRING_DENY_EFFECT,
        _ => crate::paths::PAIRING_AUTHORITY,
    };
    vec![authority("perform", target)]
}

fn action(
    id: &str,
    domain: &str,
    kind: ActionKind,
    policy: ActionPolicy,
    authority_templates: Vec<AuthorityTemplate>,
    input: SchemaDescriptor,
    output: SchemaDescriptor,
) -> ActionDescriptor {
    ActionDescriptor {
        id: id.into(),
        domain: domain.into(),
        kind,
        risk: policy.risk,
        visibility: policy.visibility,
        requires_step_up: policy.requires_step_up,
        authority_templates,
        input,
        output,
    }
}

pub(super) fn authority(verb: &str, target: &str) -> AuthorityTemplate {
    AuthorityTemplate {
        verb: verb.into(),
        target: target.into(),
    }
}

fn authority_hint_schema(id: &str) -> SchemaDescriptor {
    let mut descriptor = schema(
        id,
        "map",
        vec![
            field("action", "string", true),
            field("domain", "string", true),
            field("status", "string", true),
            field("risk", "string", true),
            field("visibility", "string", true),
            field("templates_covered", "bool", true),
            field("advisory", "bool", true),
            field("requires_step_up", "bool", true),
            field("mfa_level", "u8", true),
            field("requires_visibility_gate", "bool", true),
            field("authority", "list<authority_template>", true),
            field("why", "list<string>", true),
        ],
        vec![
            "status is step_up_required, visibility_gate_required, input_required, or preconditions_met",
            "templates_covered means unconditional structural coverage of every template, not authorization of an action",
            "preconditions_met is advisory; target policy and action-specific checks still apply",
            "input_required does not deny the action; templates can describe broader or optional targets",
            "authority.resource.access checks a concrete target and verb; actual execution remains authoritative",
        ],
    );
    descriptor.definitions.push(schema("authority_template", "map", vec![
        field("verb", "string", true),
        field("target", "path-pattern", true),
        field("coverage", "string", true),
        field("why_not", "string", false),
    ], vec!["coverage is unconditional, predicate_bound, uncovered, or invalid_template; uncovered is not a concrete denial"]));
    descriptor
}

pub(super) fn schema(
    schema_id: &str,
    value_kind: &str,
    fields: Vec<FieldDescriptor>,
    notes: Vec<&str>,
) -> SchemaDescriptor {
    SchemaDescriptor {
        schema_id: schema_id.into(),
        value_kind: value_kind.into(),
        fields,
        notes: notes.into_iter().map(str::to_string).collect(),
        definitions: Vec::new(),
        discriminator: None,
        variants: BTreeMap::new(),
    }
}

pub(crate) const MAX_SNAPSHOT_SECTIONS: u32 = 16;

fn authentication_evidence_schema() -> SchemaDescriptor {
    let mut evidence = schema(
        "authentication_evidence",
        "map",
        vec![
            field("primary", "primary_authentication", true),
            field("secondary", "secondary_authentication|null", true),
        ],
        vec![
            "proof references describe successful historical verification, not the current credential directory",
            "verified_at is Unix milliseconds sampled when verification succeeds, before later storage or issuance waits",
            "account instance, revision and credential epoch belong to the session envelope",
        ],
    );
    let mut primary = schema("primary_authentication", "map", vec![], vec![]);
    primary.discriminator = Some("method".into());
    for (method, extra) in [
        ("password", vec![]),
        ("public_key", vec![field("credential_key", "string", true)]),
        ("passkey_uv", vec![field("credential_id", "string", true)]),
    ] {
        let id = format!("primary_authentication.{method}");
        primary.variants.insert(method.into(), id.clone());
        primary.definitions.push(schema(
            &id,
            "map",
            [field("method", "string", true), field("verified_at", "i64", true)]
                .into_iter().chain(extra).collect(),
            match method {
                "password" => vec!["the account's unique password slot; no password hash or invented credential id"],
                "public_key" => vec!["credential_key is the canonical ML-DSA-65 descriptor actually selected by verification"],
                _ => vec!["credential_id is the verified base64url WebAuthn credential id; UV was verified"],
            },
        ));
    }
    let mut secondary = schema("secondary_authentication", "map", vec![], vec![]);
    secondary.discriminator = Some("method".into());
    for (method, extra) in [
        (
            "factor",
            vec![
                field("factor_id", "string", true),
                field("provider_id", "string", true),
            ],
        ),
        ("recovery_code", vec![]),
    ] {
        let id = format!("secondary_authentication.{method}");
        secondary.variants.insert(method.into(), id.clone());
        secondary.definitions.push(schema(
            &id,
            "map",
            [
                field("method", "string", true),
                field("verified_at", "i64", true),
            ]
            .into_iter()
            .chain(extra)
            .collect(),
            if method == "factor" {
                vec!["factor_id selects the stored instance; provider_id comes from that instance"]
            } else {
                vec!["consumption committed; no code, digest or recovery-list position is retained"]
            },
        ));
    }
    evidence.definitions.extend([primary, secondary]);
    evidence
}

fn snapshot_section_schema() -> SchemaDescriptor {
    let common_fields = [
        field("kind", "string", true),
        field("limit", "positive_usize", false),
        field("max_bytes", "positive_usize", false),
    ];
    let mut union = schema("snapshot_section", "map", vec![], vec![]);
    union.discriminator = Some("kind".into());
    for (kind, fields) in [
        (
            "kernel_config",
            vec![
                field("prefix", "path", true),
                field("cursor", "string", false),
            ],
        ),
        ("sessions", vec![field("cursor", "string", false)]),
        (
            "runtime",
            vec![
                field("process", "decimal_u64", false),
                field("cursor", "decimal_u64", false),
                field("include_recent_facts", "bool", false),
                field("fact_limit", "positive_usize", false),
            ],
        ),
    ] {
        let schema_id = format!("snapshot_section.{kind}");
        union.variants.insert(kind.into(), schema_id.clone());
        union.definitions.push(schema(
            &schema_id,
            "map",
            common_fields.iter().cloned().chain(fields).collect(),
            vec![],
        ));
    }
    union
}

fn fact_page_schema(schema_id: &str) -> SchemaDescriptor {
    schema(
        schema_id,
        "map",
        vec![
            field("items", "list<fact_summary>", true),
            field("from", "decimal_u64", true),
            field("next", "decimal_u64|null", true),
            field("end", "decimal_u64", true),
            field("order", "forward|reverse", true),
            field("complete", "bool", true),
            field("examined", "usize", true),
            field("encoded_bytes", "usize", true),
            field("process", "decimal_u64", false),
            field("partial", "bool", false),
            field("partial_reason", "string", false),
        ],
        vec![
            "decimal_u64 inputs accept non-negative integers or decimal strings; cursor and fact ID outputs use exact decimal strings",
            "from is inclusive and end is exclusive; reverse pages shrink their upper bound; append bounds do not freeze completion updates",
            "next=null and complete=true mean the interval is exhausted; an empty items list can still have a continuation",
            "limit bounds returned rows; max_examined bounds storage candidates including filtered rows; max_bytes bounds stored Fact JSON bytes before copying or decoding",
            "encoded_bytes is the sum of returned Fact JSON lengths, not the projected response or heap size",
            "max_bytes is capped by console.queries.max_page_bytes (at most 262144), independently of transport; max_examined defaults to max(limit, 4096) and is capped at 65536",
        ],
    )
}

pub(super) fn field(name: &str, kind: &str, required: bool) -> FieldDescriptor {
    FieldDescriptor {
        name: name.into(),
        kind: kind.into(),
        required,
        stable_id: None,
        semantic_kind: None,
        ref_target_type: None,
        sensitivity: None,
        read_only: false,
        computed: false,
        max_items: None,
    }
}

fn semantic_field(name: &str, kind: &str, required: bool, semantic_kind: &str) -> FieldDescriptor {
    FieldDescriptor {
        semantic_kind: Some(semantic_kind.into()),
        stable_id: Some(name.into()),
        sensitivity: Some("public_control".into()),
        ..field(name, kind, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{registry::DescriptorRegistry, service::admission::validate_call};

    #[test]
    fn runtime_discovery_declares_the_current_submission_retry_scope() -> anyhow::Result<()> {
        let registry = DescriptorRegistry::new();
        let describe = registry
            .action_by_id(ACTION_RUNTIME_DESCRIBE)
            .context("runtime discovery descriptor")?;
        ensure!(describe.output.fields.iter().any(|field| field
            == &super::field("submission_retry_scope", "submission_retry_scope", true)));
        let scope = describe
            .output
            .definitions
            .iter()
            .find(|definition| definition.schema_id == "submission_retry_scope")
            .context("submission retry scope definition")?;
        ensure!(scope == &submission_retry_scope_schema());
        let identity = submission_identity_schema();
        ensure!(scope.fields.len() == 2);
        ensure!(scope.fields.iter().all(|field| field.required
            && field.kind == "string"
            && identity.fields.contains(field)));
        ensure!(scope.fields.iter().any(|field| field.name == "retry_epoch"
            && field.semantic_kind.as_deref() == Some("canonical_unsigned_decimal")));
        Ok(())
    }
    use anyhow::{Context, ensure};

    fn identity_input(epoch: Value) -> Value {
        Value::map(BTreeMap::from([
            (
                "registry_instance".into(),
                Value::string("host-instance".into()),
            ),
            ("retry_epoch".into(), epoch),
            ("nonce".into(), Value::string("request-nonce".into())),
        ]))
    }

    fn submission_call(id: &str, identity: Option<Value>) -> ActionCall {
        let mut fields = if id == ACTION_RUNTIME_OPERATION_SUBMIT {
            BTreeMap::from([
                (
                    "target".into(),
                    Value::string("state://application/item".into()),
                ),
                ("method".into(), Value::string("read".into())),
            ])
        } else {
            BTreeMap::from([("source".into(), Value::string("{}".into()))])
        };
        if let Some(identity) = identity {
            fields.insert("submission_identity".into(), identity);
        }
        ActionCall {
            action: id.into(),
            input: Value::map(fields),
            ..Default::default()
        }
    }

    #[test]
    fn lookup_registry_contract_matches_owned_metadata_admission() -> anyhow::Result<()> {
        let registry = DescriptorRegistry::new();
        let lookup = registry
            .action_by_id(ACTION_RUNTIME_SUBMISSION_LOOKUP)
            .context("submission lookup descriptor")?;
        let get = registry
            .action_by_id(ACTION_RUNTIME_EXECUTION_GET)
            .context("execution get descriptor")?;
        ensure!(lookup.kind == ActionKind::View);
        ensure!(lookup.risk == get.risk);
        ensure!(lookup.visibility == get.visibility);
        ensure!(lookup.requires_step_up == get.requires_step_up);
        ensure!(lookup.authority_templates == get.authority_templates);
        ensure!(
            lookup.input.fields == vec![field("submission_identity", "submission_identity", true)]
        );
        ensure!(
            lookup.output.fields
                == vec![
                    field("evidence", "unproven|preparing|accepted|retired", true),
                    field("execution", "execution_reference|null", true),
                ]
        );
        ensure!(lookup.output.definitions == vec![execution_reference_schema()]);
        ensure!(!action_descriptors().iter().any(|descriptor| {
            descriptor.id.starts_with("runtime.submission.") && descriptor.kind != ActionKind::View
        }));
        Ok(())
    }

    #[test]
    fn root_identity_is_optional_only_for_submit_inputs() -> anyhow::Result<()> {
        let registry = DescriptorRegistry::new();
        for id in [
            ACTION_RUNTIME_OPERATION_SUBMIT,
            ACTION_RUNTIME_PROGRAM_SUBMIT,
        ] {
            validate_call(&registry, &submission_call(id, None))?;
            for epoch in ["0", "1", "18446744073709551615"] {
                validate_call(
                    &registry,
                    &submission_call(id, Some(identity_input(Value::string(epoch.into())))),
                )?;
            }
            let descriptor = registry.action_by_id(id).context("submit descriptor")?;
            ensure!(
                descriptor
                    .input
                    .fields
                    .iter()
                    .any(|field| field.name == "submission_identity"
                        && field.kind == "submission_identity"
                        && !field.required)
            );
            ensure!(
                descriptor
                    .input
                    .definitions
                    .iter()
                    .any(|definition| definition == &submission_identity_schema())
            );
        }
        for (submit, call) in [
            (
                ACTION_RUNTIME_OPERATION_SUBMIT,
                ACTION_RUNTIME_OPERATION_INVOKE,
            ),
            (ACTION_RUNTIME_PROGRAM_SUBMIT, ACTION_RUNTIME_PROGRAM_RUN),
        ] {
            let mut guarded =
                submission_call(submit, Some(identity_input(Value::string("0".into()))));
            guarded.action = call.into();
            ensure!(validate_call(&registry, &guarded).is_err());
        }
        Ok(())
    }

    #[test]
    fn lookup_and_submit_validate_identity_maps_before_dispatch() -> anyhow::Result<()> {
        let registry = DescriptorRegistry::new();
        let valid = identity_input(Value::string("0".into()));
        let mut malformed = vec![
            Value::null(),
            Value::integer(1),
            Value::string("nonce".into()),
            Value::map(BTreeMap::new()),
        ];
        for epoch in [
            Value::integer(0),
            Value::integer(-1),
            Value::null(),
            Value::string(String::new()),
        ] {
            malformed.push(identity_input(epoch));
        }
        for name in ["registry_instance", "retry_epoch", "nonce"] {
            let mut missing = valid.clone().into_map().context("identity map")?;
            missing.remove(name);
            malformed.push(Value::from(missing));
            let mut wrong_type = valid.clone().into_map().context("identity map")?;
            wrong_type.insert(name.into(), Value::integer(1))?;
            malformed.push(Value::from(wrong_type));
        }
        let mut unknown = valid.clone().into_map().context("identity map")?;
        unknown.insert("sid".into(), Value::string("session".into()))?;
        malformed.push(Value::from(unknown));
        for id in [
            ACTION_RUNTIME_SUBMISSION_LOOKUP,
            ACTION_RUNTIME_OPERATION_SUBMIT,
            ACTION_RUNTIME_PROGRAM_SUBMIT,
        ] {
            let make_call = |identity| {
                if id == ACTION_RUNTIME_SUBMISSION_LOOKUP {
                    ActionCall {
                        action: id.into(),
                        input: Value::map(BTreeMap::from([(
                            "submission_identity".into(),
                            identity,
                        )])),
                        ..Default::default()
                    }
                } else {
                    submission_call(id, Some(identity))
                }
            };
            validate_call(&registry, &make_call(valid.clone()))?;
            for identity in &malformed {
                ensure!(validate_call(&registry, &make_call(identity.clone())).is_err());
            }
        }
        ensure!(
            validate_call(
                &registry,
                &ActionCall {
                    action: ACTION_RUNTIME_SUBMISSION_LOOKUP.into(),
                    input: Value::map(BTreeMap::new()),
                    ..Default::default()
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn submit_output_preserves_original_reference_after_retirement() -> anyhow::Result<()> {
        let registry = DescriptorRegistry::new();
        for id in [
            ACTION_RUNTIME_OPERATION_SUBMIT,
            ACTION_RUNTIME_PROGRAM_SUBMIT,
        ] {
            let descriptor = registry.action_by_id(id).context("submit descriptor")?;
            ensure!(
                descriptor
                    .output
                    .fields
                    .iter()
                    .any(|field| field.name == "execution"
                        && field.kind == "execution_reference"
                        && field.required)
            );
            ensure!(
                descriptor
                    .output
                    .fields
                    .iter()
                    .any(|field| field.name == "submission_evidence"
                        && field.kind == "accepted|retired"
                        && !field.required)
            );
            ensure!(
                descriptor
                    .output
                    .fields
                    .iter()
                    .all(|field| field.name == "execution" || !field.required)
            );
            let record = descriptor
                .output
                .definitions
                .iter()
                .find(|definition| definition.schema_id == "execution_record")
                .context("accepted execution record schema")?;
            ensure!(record.fields == execution_record_fields());
        }
        Ok(())
    }

    #[test]
    fn execution_record_descriptors_have_no_lifecycle_audit_state() -> anyhow::Result<()> {
        let fields = execution_record_fields();
        ensure!(!fields.iter().any(|field| field.name == "audit_recorded"));
        ensure!(fields.iter().any(|field| {
            field.name == "cleanup_status" && field.kind == "string" && field.required
        }));
        for descriptor in runtime_descriptors() {
            if let Some(record) = descriptor
                .output
                .definitions
                .iter()
                .find(|schema| schema.schema_id == "execution_record")
            {
                ensure!(record.fields == fields);
                if descriptor
                    .output
                    .fields
                    .iter()
                    .any(|field| field.name == "execution_id")
                    && !matches!(
                        descriptor.id.as_str(),
                        ACTION_RUNTIME_OPERATION_SUBMIT | ACTION_RUNTIME_PROGRAM_SUBMIT
                    )
                {
                    ensure!(descriptor.output.fields == fields);
                }
            }
        }
        let output = execution_output_schema("test", fields.clone(), vec![]);
        let record = output
            .definitions
            .iter()
            .find(|schema| schema.schema_id == "execution_record")
            .context("execution record definition")?;
        ensure!(record.fields == fields);
        Ok(())
    }
}
