//! Lossless idempotency key material, hashed only at the storage boundary.
//!
//! Default keys retain the full operation identity. Business keys deliberately
//! span executions, but remain bound to identity, call position, resource,
//! method, output representation and adaptation phase. Creating an asynchronous
//! process and executing its effect can never publish into the same cache slot.

use crate::{IdentityRef, MethodId, OperationId, OutputMode, ResourceId, Value};
use alloc::string::String;

/// Reserved input field for a business key shared across operation identities.
pub const IDEM_KEY_FIELD: &str = "_idem_key";

/// The opened target and result representation associated with a cached effect.
#[derive(Clone, Copy, Debug)]
pub struct KeyScope {
    /// Resource selected by the admitted handle.
    pub resource: ResourceId,
    /// Method in that resource's interface.
    pub method: MethodId,
    /// Representation returned to the caller.
    pub output: OutputMode,
    /// Whether this call publishes a process reference for a separately run effect.
    pub creates_process: bool,
}

/// Derive canonical key material without reducing business keys to a short hash.
/// A host hashes the complete returned string into its storage key.
pub fn derive_key(
    op_id: OperationId,
    acting: IdentityRef,
    input: &Value,
    scope: KeyScope,
) -> String {
    let output = match scope.output {
        OutputMode::Unary => "unary".into(),
        OutputMode::Stream => "stream".into(),
        OutputMode::Collect { limit } => format!("collect:{limit}"),
        OutputMode::SinkOnly => "sink".into(),
        OutputMode::AsyncProcess => "process".into(),
    };
    let prefix = format!(
        "xolotl-idem-v2/{}/{}/{}/{}/{}/",
        acting.get(),
        scope.resource.get(),
        scope.method.get(),
        output,
        if scope.creates_process {
            "spawn"
        } else {
            "call"
        }
    );
    match business_key(input) {
        Some(business) => format!(
            "{prefix}business/{}/{}/{business}",
            op_id.position.get(),
            business.len()
        ),
        None => format!("{prefix}operation/{op_id}"),
    }
}

fn business_key(input: &Value) -> Option<&str> {
    input
        .as_map()?
        .get(IDEM_KEY_FIELD)?
        .as_str()
        .filter(|key| !key.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionId, InvocationId, NodeId, ProcessId};
    use alloc::collections::BTreeMap;

    fn op() -> OperationId {
        OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(7),
            NodeId::new(3),
            0,
        )
    }

    fn scope() -> KeyScope {
        KeyScope {
            resource: ResourceId::new(8),
            method: MethodId::new(2),
            output: OutputMode::Unary,
            creates_process: false,
        }
    }

    fn input(key: &str) -> Value {
        Value::map(BTreeMap::from([(
            IDEM_KEY_FIELD.into(),
            Value::string(key.into()),
        )]))
    }

    #[test]
    fn default_key_preserves_all_operation_coordinates() {
        let key = derive_key(op(), IdentityRef::ROOT, &Value::null(), scope());
        assert!(key.ends_with("/operation/1/1/7/3/0"));
        for other in [
            OperationId {
                process: ProcessId::new(2),
                ..op()
            },
            OperationId {
                invocation: InvocationId::new(8),
                ..op()
            },
            OperationId {
                position: NodeId::new(4),
                ..op()
            },
            OperationId { attempt: 1, ..op() },
        ] {
            assert_ne!(
                key,
                derive_key(other, IdentityRef::ROOT, &Value::null(), scope())
            );
        }
    }

    #[test]
    fn business_keys_span_executions_without_losing_key_material() {
        let business = "orders/create/42\0operation/1/2/3/4/5";
        let value = input(business);
        let first = derive_key(op(), IdentityRef::ROOT, &value, scope());
        let independent = OperationId {
            process: ProcessId::new(2),
            invocation: InvocationId::new(8),
            attempt: 1,
            ..op()
        };
        assert_eq!(
            first,
            derive_key(independent, IdentityRef::ROOT, &value, scope())
        );
        assert!(first.ends_with(business));
        assert_ne!(
            first,
            derive_key(op(), IdentityRef::new(20), &value, scope())
        );
        assert_ne!(
            first,
            derive_key(
                OperationId {
                    position: NodeId::new(4),
                    ..op()
                },
                IdentityRef::ROOT,
                &value,
                scope()
            )
        );
    }

    #[test]
    fn resource_method_representation_and_adapter_have_separate_namespaces() {
        let value = input("order-42");
        let key = derive_key(op(), IdentityRef::ROOT, &value, scope());
        for other in [
            KeyScope {
                resource: ResourceId::new(9),
                ..scope()
            },
            KeyScope {
                method: MethodId::new(3),
                ..scope()
            },
            KeyScope {
                output: OutputMode::Stream,
                ..scope()
            },
            KeyScope {
                output: OutputMode::Collect { limit: 1 },
                ..scope()
            },
            KeyScope {
                creates_process: true,
                ..scope()
            },
        ] {
            assert_ne!(key, derive_key(op(), IdentityRef::ROOT, &value, other));
        }
        let process = KeyScope {
            output: OutputMode::AsyncProcess,
            ..scope()
        };
        assert_ne!(
            derive_key(op(), IdentityRef::ROOT, &value, process),
            derive_key(
                op(),
                IdentityRef::ROOT,
                &value,
                KeyScope {
                    creates_process: true,
                    ..process
                }
            )
        );
    }

    #[test]
    fn empty_and_mistyped_business_keys_use_operation_identity() {
        let fallback = derive_key(op(), IdentityRef::ROOT, &Value::null(), scope());
        assert_eq!(
            fallback,
            derive_key(op(), IdentityRef::ROOT, &input(""), scope())
        );
        let wrong = Value::map(BTreeMap::from([(IDEM_KEY_FIELD.into(), Value::integer(7))]));
        assert_eq!(
            fallback,
            derive_key(op(), IdentityRef::ROOT, &wrong, scope())
        );
    }
}
