//! Fixed resource, view, secret and visibility discovery contracts.

use super::*;

pub(crate) fn resource_type_summaries(types: &BTreeMap<&str, Value>) -> Value {
    const SUMMARY_FIELDS: [&str; 5] = [
        "resource_type",
        "title",
        "default_view",
        "read_action",
        "update_action",
    ];
    Value::list(
        types
            .values()
            .map(|descriptor| {
                Value::map(
                    SUMMARY_FIELDS
                        .into_iter()
                        .filter_map(|key| {
                            descriptor
                                .as_map()?
                                .get(key)
                                .map(|value| (key.into(), value.clone()))
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

pub(crate) fn resource_type_registry() -> &'static BTreeMap<&'static str, Value> {
    static DESCRIPTORS: OnceLock<BTreeMap<&'static str, Value>> = OnceLock::new();
    DESCRIPTORS.get_or_init(|| {
        BTreeMap::from([
            (
                "config.entry",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "config.entry",
                        title: "Config entry",
                        default_view: "config.entries",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_CONFIG_READ,
                        list: Some(ACTION_CONFIG_LIST),
                        update: Some(ACTION_CONFIG_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "path",
                            "path",
                            true,
                            "path",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "value",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["path", "expected_version"],
                ),
            ),
            (
                "access.user",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "access.user",
                        title: "Console user",
                        default_view: "access.users",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_ACCESS_USER_READ,
                        list: Some(ACTION_ACCESS_USER_LIST),
                        update: Some(ACTION_ACCESS_USER_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "username",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "status",
                            "string",
                            true,
                            "enum",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "roles",
                            "list<string>",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "grants",
                            "list<string>",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "authority_ceiling",
                            "list<string>",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "account_id",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "identity_path",
                            "path",
                            true,
                            "path",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "bootstrap_owner",
                            "bool",
                            true,
                            "enum",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "created_by",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "created_at",
                            "i64",
                            true,
                            "timestamp",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "version",
                            "i64",
                            true,
                            "revision",
                            "management_state",
                            true,
                        ),
                    ],
                    vec!["username", "status"],
                ),
            ),
            (
                "access.role",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "access.role",
                        title: "Console role",
                        default_view: "access.roles",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_ACCESS_ROLE_READ,
                        list: Some(ACTION_ACCESS_ROLE_LIST),
                        update: Some(ACTION_ACCESS_ROLE_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "role",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "grants",
                            "list<string>",
                            false,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "frozen",
                            "bool",
                            false,
                            "enum",
                            "management_state",
                            false,
                        ),
                    ],
                    vec!["role", "frozen"],
                ),
            ),
            (
                "access.session",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "access.session",
                        title: "Console session",
                        default_view: "access.sessions",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_ACCESS_SESSION_LIST,
                        list: Some(ACTION_ACCESS_SESSION_LIST),
                        update: Some(ACTION_ACCESS_SESSION_REVOKE),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "sid",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "username",
                            "string",
                            false,
                            "resource_ref",
                            "management_state",
                            true,
                        ),
                        semantic_contract_field(
                            "mfa_level",
                            "u8",
                            false,
                            "enum",
                            "public_control",
                            true,
                        ),
                        semantic_contract_field(
                            "issued_at",
                            "i64",
                            true,
                            "timestamp",
                            "public_control",
                            true,
                        ),
                        semantic_contract_field(
                            "authenticated_at",
                            "i64",
                            true,
                            "timestamp",
                            "public_control",
                            true,
                        ),
                        semantic_contract_field(
                            "expires_at",
                            "i64",
                            false,
                            "duration",
                            "public_control",
                            true,
                        ),
                    ],
                    vec!["sid", "username", "mfa_level"],
                ),
            ),
            (
                "external.installation",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "external.installation",
                        title: "External installation",
                        default_view: "external.installations",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_EXTERNAL_INSTALLATION_READ,
                        list: Some(ACTION_EXTERNAL_INSTALLATION_LIST),
                        update: Some(ACTION_EXTERNAL_INSTALLATION_UPDATE),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "id",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_installation_epoch",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["id"],
                ),
            ),
            (
                "external.manifest",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "external.manifest",
                        title: "External manifest",
                        default_view: "external.manifests",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_EXTERNAL_MANIFEST_READ,
                        list: Some(ACTION_EXTERNAL_MANIFEST_LIST),
                        update: Some(ACTION_EXTERNAL_MANIFEST_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "platform",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["platform"],
                ),
            ),
            (
                "projection.in_process.status",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "projection.in_process.status",
                        title: "In-process projection status",
                        default_view: "projection.in_process.status",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
                        list: Some(ACTION_PROJECTION_IN_PROCESS_STATUS_LIST),
                        update: None,
                        validate: None,
                    },
                    vec![semantic_contract_field(
                        "id",
                        "string",
                        true,
                        "resource_ref",
                        "management_state",
                        false,
                    )],
                    vec!["id"],
                ),
            ),
            (
                "inference.backend",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "inference.backend",
                        title: "Inference backend",
                        default_view: "inference.backends",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_INFERENCE_BACKEND_READ,
                        list: Some(ACTION_INFERENCE_BACKEND_LIST),
                        update: Some(ACTION_INFERENCE_BACKEND_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "id",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["id"],
                ),
            ),
            (
                "inference.model",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "inference.model",
                        title: "Inference model",
                        default_view: "inference.models",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_INFERENCE_MODEL_READ,
                        list: Some(ACTION_INFERENCE_MODEL_LIST),
                        update: Some(ACTION_INFERENCE_MODEL_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "id",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["id"],
                ),
            ),
            (
                "inference.group",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "inference.group",
                        title: "Inference group",
                        default_view: "inference.groups",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_INFERENCE_GROUP_READ,
                        list: Some(ACTION_INFERENCE_GROUP_LIST),
                        update: Some(ACTION_INFERENCE_GROUP_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "name",
                            "string",
                            true,
                            "resource_ref",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["name"],
                ),
            ),
            (
                "inference.routing",
                resource_type_descriptor(
                    ResourceTypeDescriptorMeta {
                        resource_type: "inference.routing",
                        title: "Inference routing",
                        default_view: "inference.routing",
                    },
                    ResourceTypeDescriptorActions {
                        read: ACTION_INFERENCE_ROUTING_READ,
                        list: None,
                        update: Some(ACTION_INFERENCE_ROUTING_WRITE_CAS),
                        validate: None,
                    },
                    vec![
                        semantic_contract_field(
                            "def",
                            "value",
                            true,
                            "json_value",
                            "management_state",
                            false,
                        ),
                        semantic_contract_field(
                            "expected_version",
                            "u64|null",
                            false,
                            "revision",
                            "public_control",
                            false,
                        ),
                    ],
                    vec!["default_group"],
                ),
            ),
        ])
    })
}

/// Return one fixed resource view descriptor encoded as a Xolotl value.
pub(crate) fn resource_view_registry() -> &'static BTreeMap<&'static str, Value> {
    static DESCRIPTORS: OnceLock<BTreeMap<&'static str, Value>> = OnceLock::new();
    DESCRIPTORS.get_or_init(|| {
        BTreeMap::from([
            (
                "config.entries",
                resource_view_descriptor(
                    "config.entries",
                    "config.entry",
                    ACTION_CONFIG_LIST,
                    STREAM_STATE_WATCH,
                    vec!["path", "value_kind", "revision"],
                ),
            ),
            (
                "access.users",
                resource_view_descriptor(
                    "access.users",
                    "access.user",
                    ACTION_ACCESS_USER_LIST,
                    STREAM_STATE_WATCH,
                    vec!["username", "status", "mfa_level", "roles"],
                ),
            ),
            (
                "access.roles",
                resource_view_descriptor(
                    "access.roles",
                    "access.role",
                    ACTION_ACCESS_ROLE_LIST,
                    STREAM_STATE_WATCH,
                    vec!["role", "grant_count", "frozen"],
                ),
            ),
            (
                "access.sessions",
                resource_view_descriptor(
                    "access.sessions",
                    "access.session",
                    ACTION_ACCESS_SESSION_LIST,
                    STREAM_AUDIT_FACTS,
                    vec!["sid", "username", "mfa_level", "expires_at"],
                ),
            ),
            (
                "external.installations",
                resource_view_descriptor(
                    "external.installations",
                    "external.installation",
                    ACTION_EXTERNAL_INSTALLATION_LIST,
                    STREAM_STATE_WATCH,
                    vec!["id", "platform", "version"],
                ),
            ),
            (
                "external.manifests",
                resource_view_descriptor(
                    "external.manifests",
                    "external.manifest",
                    ACTION_EXTERNAL_MANIFEST_LIST,
                    STREAM_STATE_WATCH,
                    vec!["platform", "version", "projection_count"],
                ),
            ),
            (
                "projection.in_process.status",
                resource_view_descriptor(
                    "projection.in_process.status",
                    "projection.in_process.status",
                    ACTION_PROJECTION_IN_PROCESS_STATUS_LIST,
                    STREAM_STATE_WATCH,
                    vec![
                        "id",
                        "phase",
                        "implementation",
                        "desired_version",
                        "active_version",
                        "error_code",
                    ],
                ),
            ),
            (
                "inference.backends",
                resource_view_descriptor(
                    "inference.backends",
                    "inference.backend",
                    ACTION_INFERENCE_BACKEND_LIST,
                    STREAM_STATE_WATCH,
                    vec!["id", "dialect", "base_url", "version"],
                ),
            ),
            (
                "inference.models",
                resource_view_descriptor(
                    "inference.models",
                    "inference.model",
                    ACTION_INFERENCE_MODEL_LIST,
                    STREAM_STATE_WATCH,
                    vec!["id", "backend_id", "provider_model", "version"],
                ),
            ),
            (
                "inference.groups",
                resource_view_descriptor(
                    "inference.groups",
                    "inference.group",
                    ACTION_INFERENCE_GROUP_LIST,
                    STREAM_STATE_WATCH,
                    vec!["name", "policy", "models", "version"],
                ),
            ),
            (
                "inference.routing",
                resource_view_descriptor(
                    "inference.routing",
                    "inference.routing",
                    ACTION_INFERENCE_ROUTING_READ,
                    STREAM_STATE_WATCH,
                    vec!["default_group", "max_retries", "version"],
                ),
            ),
        ])
    })
}

/// Return the secret custody catalog exposed by `secret.catalog`.
pub(crate) fn secret_catalog_value() -> Value {
    let rows = vec![
        secret_row(
            crate::paths::VAULT_CREDENTIAL_RESOURCE,
            SecretClass::NonRecoverableSecret,
            "primary credentials, factor verifiers and recovery hashes are vault-only; authorized callers may replace credentials",
        ),
        secret_row(
            crate::paths::SESSION_STORE_RESOURCE,
            SecretClass::NonRecoverableSecret,
            "private session aggregates include bearer verifiers; authorized management returns summaries, never verifiers",
        ),
        secret_row(
            "pairing.display_secret",
            SecretClass::OneTimeSecret,
            "pairing display secrets are available only on the create/replace edge",
        ),
    ];
    Value::list(rows)
}

/// Return root data authority and visibility-gate metadata.
pub(crate) fn visibility_authority_value() -> Value {
    let mut root = BTreeMap::new();
    root.insert(
        "root_can_view_all_business_data".into(),
        Value::boolean(true),
    );
    root.insert(
        "requires_step_up_for_protected_payload".into(),
        Value::boolean(true),
    );
    root.insert(
        "bypasses_operation_fact_policy".into(),
        Value::boolean(false),
    );
    root.insert("business_prefix".into(), Value::string("state://**".into()));
    root.insert(
        "secret_prefix".into(),
        Value::string("state://vault/**".into()),
    );
    root.insert(
        "secret_prefix_rule".into(),
        Value::string(
            "secret.catalog exposes metadata; generic visibility reads reject vault".into(),
        ),
    );
    root.insert(
        "password_policy".into(),
        crate::credentials::password_policy_to_value(
            &crate::credentials::PasswordPolicy::default().bounded(),
        ),
    );
    root.insert(
        "lockout_policy".into(),
        crate::credentials::lockout_policy_to_value(5, 1000, 60_000),
    );
    Value::map(root)
}

fn secret_row(path: &str, class: SecretClass, policy: &str) -> Value {
    let mut row = BTreeMap::new();
    row.insert("path".into(), Value::string(path.into()));
    row.insert("class".into(), to_value(class));
    row.insert("policy".into(), Value::string(policy.into()));
    Value::map(row)
}

struct ResourceTypeDescriptorMeta<'a> {
    resource_type: &'a str,
    title: &'a str,
    default_view: &'a str,
}

struct ResourceTypeDescriptorActions<'a> {
    read: &'a str,
    list: Option<&'a str>,
    update: Option<&'a str>,
    validate: Option<&'a str>,
}

fn resource_type_descriptor(
    meta: ResourceTypeDescriptorMeta<'_>,
    actions: ResourceTypeDescriptorActions<'_>,
    fields: Vec<Value>,
    display_fields: Vec<&str>,
) -> Value {
    value_map([
        ("resource_type", Value::string(meta.resource_type.into())),
        ("title", Value::string(meta.title.into())),
        ("default_view", Value::string(meta.default_view.into())),
        ("read_action", Value::string(actions.read.into())),
        (
            "list_action",
            actions
                .list
                .map_or(Value::null(), |action| Value::string(action.into())),
        ),
        (
            "update_action",
            actions
                .update
                .map_or(Value::null(), |action| Value::string(action.into())),
        ),
        (
            "validate_action",
            actions
                .validate
                .map_or(Value::null(), |action| Value::string(action.into())),
        ),
        ("revision_field", actions.update.and_then(|id| {
            action_descriptors().iter().find(|action| action.id == id)
        }).filter(|action| action.input.fields.iter().any(|field| field.name == "expected_version"))
            .map_or(Value::null(), |_| Value::string("expected_version".into()))),
        ("fields", Value::list(fields)),
        (
            "display_fields",
            Value::list(
                display_fields
                    .into_iter()
                    .map(|field| Value::string(field.into()))
                    .collect(),
            ),
        ),
        (
            "notes",
            Value::list(vec![
                Value::string("descriptor supplies semantic edit metadata only; every write still calls the fixed action descriptor".into()),
                Value::string("revision_field names the CAS argument of the update action; null means that action does not expose CAS".into()),
            ]),
        ),
    ])
}

fn semantic_contract_field(
    name: &str,
    kind: &str,
    required: bool,
    semantic_kind: &str,
    sensitivity: &str,
    read_only: bool,
) -> Value {
    value_map([
        ("name", Value::string(name.into())),
        ("kind", Value::string(kind.into())),
        ("required", Value::boolean(required)),
        ("stable_id", Value::string(name.into())),
        ("semantic_kind", Value::string(semantic_kind.into())),
        ("sensitivity", Value::string(sensitivity.into())),
        ("read_only", Value::boolean(read_only)),
        ("computed", Value::boolean(false)),
    ])
}

fn resource_view_descriptor(
    view: &str,
    resource_type: &str,
    read_action: &str,
    refresh_stream: &str,
    projection_fields: Vec<&str>,
) -> Value {
    value_map([
        ("view", Value::string(view.into())),
        ("resource_type", Value::string(resource_type.into())),
        ("read_action", Value::string(read_action.into())),
        (
            "query_schema",
            action_descriptors()
                .iter()
                .find(|d| d.id == read_action)
                .map(|d| to_value(&d.input))
                .unwrap_or(Value::null()),
        ),
        (
            "projection_schema",
            action_descriptors()
                .iter()
                .find(|d| d.id == read_action)
                .map(|d| to_value(&d.output))
                .unwrap_or(Value::null()),
        ),
        (
            "pagination",
            Value::string(
                if read_action == ACTION_INFERENCE_ROUTING_READ {
                    "none"
                } else {
                    "cursor"
                }
                .into(),
            ),
        ),
        ("filtering", Value::list(vec![])),
        ("sorting", Value::list(vec![])),
        (
            "refresh_stream",
            if view == "external.installations" {
                Value::null()
            } else {
                Value::string(refresh_stream.into())
            },
        ),
        (
            "suggested_display_fields",
            Value::list(
                projection_fields
                    .into_iter()
                    .map(|field| Value::string(field.into()))
                    .collect(),
            ),
        ),
    ])
}

fn value_map(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::map(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}
