use super::*;
use crate::protocol::ActionResult;
use anyhow::{Context, Result, ensure};

#[test]
fn reconciliation_sidecar_survives_success_and_failure_frames() -> Result<()> {
    let mut unresolved = xolotl_types::UnresolvedOperations::default();
    ensure!(unresolved.record("1/2/3/4/0"));
    unresolved.identities_incomplete = true;
    let mut result = ActionResult::value(Value::integer(7), 3, 2);
    result.unresolved_operations = Some(Box::new(unresolved.clone()));
    let bytes = encode_server_frame(&ServerFrame::Reply { id: 1, result }, 4096)?;
    let encoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    let Some(pb::console_frame::Frame::Reply(reply)) = encoded.frame else {
        anyhow::bail!("expected reply frame")
    };
    let attached = reply
        .result
        .context("action result")?
        .unresolved_operations
        .context("success reconciliation sidecar")?;
    ensure!(attached.operation_ids == ["1/2/3/4/0"]);
    ensure!(attached.identities_incomplete);

    let failure = ConsoleFailure {
        unresolved_operations: Some(Box::new(unresolved)),
        runtime_completion: Some(Box::new(Value::integer(37))),
        ..ConsoleFailure::new(ConsoleErrorCode::Internal, "operation failed".into())
    };
    let bytes = encode_server_frame(
        &ServerFrame::Error {
            id: Some(2),
            failure,
        },
        4096,
    )?;
    let encoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    let Some(pb::console_frame::Frame::Error(error)) = encoded.frame else {
        anyhow::bail!("expected error frame")
    };
    ensure!(
        xolotl_proto::value_from_pb(
            error
                .runtime_completion
                .as_deref()
                .context("retained body evidence")?
        )? == Value::integer(37)
    );
    let attached = error
        .unresolved_operations
        .context("failure reconciliation sidecar")?;
    ensure!(attached.operation_ids == ["1/2/3/4/0"]);
    ensure!(attached.identities_incomplete);
    Ok(())
}

#[test]
fn uncertain_effect_detail_survives_error_frames_and_respects_budget() -> Result<()> {
    let failure = ConsoleFailure {
        outcome_unknown: Some(Box::new(crate::OutcomeUnknownDetail {
            operation_ids: vec!["1/2/3/4/0".into(), "1/2/4/5/0".into()],
            reason: "delivery_or_session_lost".into(),
        })),
        ..ConsoleFailure::new(
            ConsoleErrorCode::OutcomeUnknown,
            "runtime effect outcome is unknown".into(),
        )
    };
    let frame = ServerFrame::Error {
        id: Some(7),
        failure: failure.clone(),
    };
    let bytes = encode_server_frame(&frame, 4096)?;
    let encoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    let Some(pb::console_frame::Frame::Error(error)) = encoded.frame else {
        anyhow::bail!("expected error frame")
    };
    ensure!(error.code == pb::ConsoleErrorCode::OutcomeUnknown as i32);
    ensure!(error.request_id == Some(7));
    let detail = error.outcome_unknown.context("unknown detail")?;
    ensure!(detail.operation_ids == ["1/2/3/4/0", "1/2/4/5/0"]);
    ensure!(detail.reason == "delivery_or_session_lost");
    ensure!(matches!(
        encode_server_frame(&frame, bytes.len() - 1),
        Err(FrameEncodeError::FrameBytes { .. })
    ));

    let budget = ConversionBudget::new(
        failure.message.len()
            + detail.operation_ids.len()
            + detail.operation_ids.iter().map(String::len).sum::<usize>()
            + detail.reason.len()
            - 1,
    );
    ensure!(matches!(
        failure_to_pb(&failure, Some(7), budget),
        Err(FrameEncodeError::FieldBytes {
            field: "error.outcome_unknown.reason",
            ..
        })
    ));
    let mut wide = failure;
    wide.outcome_unknown
        .as_mut()
        .context("wide detail")?
        .operation_ids = vec![String::new(); 1024];
    ensure!(matches!(
        failure_to_pb(
            &wide,
            None,
            ConversionBudget::new(wide.message.len() + 1023)
        ),
        Err(FrameEncodeError::FieldBytes {
            field: "error.outcome_unknown.operation_ids",
            ..
        })
    ));
    Ok(())
}

#[test]
fn mfa_instance_metadata_survives_failure_and_subscription_encoding() -> Result<()> {
    let options = crate::mfa::MfaOptions {
        factors: vec![
            crate::mfa::FactorSummary {
                factor_id: "phone".into(),
                provider_id: "totp".into(),
                label: "Phone".into(),
                created_at: i64::MIN,
                last_used_at: Some(0),
                availability: crate::mfa::FactorAvailability::Available,
            },
            crate::mfa::FactorSummary {
                factor_id: "backup".into(),
                provider_id: "totp".into(),
                label: "备用设备".into(),
                created_at: i64::MAX,
                last_used_at: None,
                availability: crate::mfa::FactorAvailability::ProviderNotInstalled,
            },
            crate::mfa::FactorSummary {
                factor_id: "paused".into(),
                provider_id: "push".into(),
                label: "Paused by host".into(),
                created_at: 42,
                last_used_at: Some(43),
                availability: crate::mfa::FactorAvailability::AuthenticationDisabled,
            },
        ],
        recovery_code_available: true,
    };
    let failure = ConsoleFailure {
        mfa: Some(Box::new(options)),
        required_mfa_level: Some(2),
        ..ConsoleFailure::new(ConsoleErrorCode::StepUpRequired, "MFA required".into())
    };
    let expected = pb::MfaOptions {
        factors: vec![
            pb::MfaFactor {
                factor_id: "phone".into(),
                provider_id: "totp".into(),
                label: "Phone".into(),
                created_at: i64::MIN,
                last_used_at: Some(0),
                availability: pb::FactorAvailability::Available as i32,
            },
            pb::MfaFactor {
                factor_id: "backup".into(),
                provider_id: "totp".into(),
                label: "备用设备".into(),
                created_at: i64::MAX,
                last_used_at: None,
                availability: pb::FactorAvailability::ProviderNotInstalled as i32,
            },
            pb::MfaFactor {
                factor_id: "paused".into(),
                provider_id: "push".into(),
                label: "Paused by host".into(),
                created_at: 42,
                last_used_at: Some(43),
                availability: pb::FactorAvailability::AuthenticationDisabled as i32,
            },
        ],
        recovery_code_available: true,
    };
    for frame in [
        ServerFrame::Error {
            id: Some(31),
            failure: failure.clone(),
        },
        ServerFrame::Event {
            stream: 12,
            event: ConsoleEvent::SubscriptionClosed {
                reason: "step-up required".into(),
                failure: Some(Box::new(failure)),
            },
        },
    ] {
        let bytes = encode_server_frame(&frame, 4096)?;
        let encoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
        let error = match encoded.frame.context("frame")? {
            pb::console_frame::Frame::Error(error) => error,
            pb::console_frame::Frame::Event(event) => {
                let Some(pb::console_event::Kind::Closed(closed)) =
                    event.event.and_then(|v| v.kind)
                else {
                    anyhow::bail!("expected subscription closure");
                };
                closed.failure.context("closure failure")?
            }
            other => anyhow::bail!("unexpected failure frame: {other:?}"),
        };
        ensure!(error.mfa.as_ref() == Some(&expected));
        ensure!(error.required_mfa_level == Some(2));
        ensure!(matches!(
            encode_server_frame(&frame, bytes.len() - 1),
            Err(FrameEncodeError::FrameBytes { .. })
        ));
    }
    Ok(())
}

#[test]
fn mfa_conversion_bounds_strings_factor_count_and_optional_metadata() -> Result<()> {
    let mut options = crate::mfa::MfaOptions {
        factors: vec![crate::mfa::FactorSummary {
            factor_id: "abc".into(),
            provider_id: "def".into(),
            label: "ghi".into(),
            created_at: 0,
            last_used_at: None,
            availability: crate::mfa::FactorAvailability::ProviderNotInstalled,
        }],
        recovery_code_available: false,
    };
    ensure!(
        mfa_options_to_pb(&options, &mut ConversionBudget::new(11))?
            .factors
            .len()
            == 1
    );
    ensure!(matches!(
        mfa_options_to_pb(&options, &mut ConversionBudget::new(10)),
        Err(FrameEncodeError::FieldBytes {
            field: "error.mfa.factors.label",
            ..
        })
    ));
    options.factors[0].last_used_at = Some(0);
    ensure!(matches!(
        mfa_options_to_pb(&options, &mut ConversionBudget::new(11)),
        Err(FrameEncodeError::FieldBytes {
            field: "error.mfa.factors.last_used_at",
            ..
        })
    ));
    ensure!(
        mfa_options_to_pb(&options, &mut ConversionBudget::new(12))?.factors[0].last_used_at
            == Some(0)
    );
    let failure = ConsoleFailure {
        mfa: Some(Box::new(options)),
        ..ConsoleFailure::new(ConsoleErrorCode::StepUpRequired, "x".into())
    };
    ensure!(failure_to_pb(&failure, None, ConversionBudget::new(13)).is_ok());
    ensure!(matches!(
        failure_to_pb(&failure, None, ConversionBudget::new(12)),
        Err(FrameEncodeError::FieldBytes { .. })
    ));

    let mut empty = crate::mfa::MfaOptions {
        factors: Vec::new(),
        recovery_code_available: false,
    };
    ensure!(
        mfa_options_to_pb(&empty, &mut ConversionBudget::new(1))?
            .factors
            .is_empty()
    );
    ensure!(matches!(
        mfa_options_to_pb(&empty, &mut ConversionBudget::new(0)),
        Err(FrameEncodeError::FieldBytes {
            field: "error.mfa",
            ..
        })
    ));
    empty.factors = vec![
        crate::mfa::FactorSummary {
            factor_id: String::new(),
            provider_id: String::new(),
            label: String::new(),
            created_at: 0,
            last_used_at: None,
            availability: crate::mfa::FactorAvailability::ProviderNotInstalled,
        };
        1024
    ];
    ensure!(matches!(
        mfa_options_to_pb(&empty, &mut ConversionBudget::new(1024)),
        Err(FrameEncodeError::FieldBytes {
            field: "error.mfa.factors",
            ..
        })
    ));
    Ok(())
}

#[test]
fn compact_greetings_preserve_negotiation_and_security_on_the_wire() -> Result<()> {
    let metadata = crate::protocol::protocol_greeting(137, 421, 123_456);
    let mut transport = TransportSecuritySummary {
        mode: "unsafe_plaintext".into(),
        unsafe_transport: true,
        relaxations: vec!["plaintext".into(), "missing_origin".into()],
    };
    let principal = PrincipalSummary {
        username: "operator".into(),
        identity_path: "identity://console/accounts/operator-account".into(),
        mfa_level: 2,
    };
    for frame in [
        ServerFrame::HelloAccepted {
            metadata: metadata.clone(),
            transport: transport.clone(),
        },
        ServerFrame::Authenticated {
            principal: principal.clone(),
            metadata: metadata.clone(),
        },
    ] {
        // Catalog size must not affect small-frame negotiation or authentication.
        let bytes = encode_server_frame(&frame, 1024)?;
        let decoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
        let greeting = match decoded.frame.context("frame")? {
            pb::console_frame::Frame::HelloAccepted(hello) => {
                ensure!(
                    hello.transport
                        == Some(pb::TransportSecuritySummary {
                            mode: transport.mode.clone(),
                            unsafe_transport: transport.unsafe_transport,
                            relaxations: transport.relaxations.clone(),
                        })
                );
                hello.metadata
            }
            pb::console_frame::Frame::Authenticated(auth) => {
                ensure!(
                    auth.principal
                        == Some(pb::PrincipalSummary {
                            username: principal.username.clone(),
                            identity_path: principal.identity_path.clone(),
                            mfa_level: u32::from(principal.mfa_level),
                        })
                );
                auth.metadata
            }
            other => anyhow::bail!("unexpected greeting: {other:?}"),
        }
        .context("greeting")?;
        ensure!(
            greeting
                == pb::ProtocolGreeting {
                    protocol_version: u32::from(metadata.protocol_version),
                    server_name: metadata.server_name.clone(),
                    wire_encoding: metadata.encoding.clone(),
                    server_rev: metadata.server_rev,
                    registry_rev: metadata.registry_rev,
                    server_time_ms: metadata.server_time_ms,
                }
        );
    }
    // Newly carried security fields consume the same budget as the other strings.
    transport.relaxations = vec!["x".repeat(1024)];
    ensure!(matches!(
        encode_server_frame(
            &ServerFrame::HelloAccepted {
                metadata,
                transport
            },
            1024
        ),
        Err(FrameEncodeError::FieldBytes {
            field: "transport.relaxations",
            ..
        })
    ));
    Ok(())
}

fn reply(value: Value) -> ServerFrame {
    ServerFrame::Reply {
        id: u64::MAX,
        result: ActionResult::value(value, u64::MAX, 7),
    }
}

#[test]
fn exact_frame_size_includes_envelopes_and_varints() -> Result<()> {
    for value in [
        Value::null(),
        Value::integer(i64::MIN),
        Value::integer(127),
        Value::integer(128),
        Value::string("abc".into()),
    ] {
        let frame = reply(value);
        let pb = server_frame_to_pb(&frame, 4096)?;
        let size = pb.encoded_len();
        let bytes = encode_bounded(&pb, size)?;
        ensure!(bytes.len() == size);
        ensure!(
            matches!(encode_bounded(&pb, size - 1), Err(FrameEncodeError::FrameBytes { actual, limit }) if actual == size && limit == size - 1)
        );
        ensure!(pb::ConsoleFrame::decode(bytes.as_slice())? == pb);
    }
    Ok(())
}

#[test]
fn tiny_values_still_have_bounded_node_cost() -> Result<()> {
    let frame = reply(Value::list(vec![Value::null(); MAX_VALUE_NODES]));
    ensure!(matches!(
        encode_server_frame(&frame, MAX_VALUE_NODES * 16),
        Err(FrameEncodeError::Value(ValueEncodeError::Nodes {
            limit: MAX_VALUE_NODES
        }))
    ));
    Ok(())
}

#[test]
fn principal_fields_share_one_inline_budget() -> Result<()> {
    let principal = PrincipalSummary {
        username: "abc".into(),
        identity_path: "def".into(),
        mfa_level: 1,
    };
    ensure!(principal_to_pb(&principal, &mut ConversionBudget::new(6))?.username == "abc");
    ensure!(matches!(
        principal_to_pb(&principal, &mut ConversionBudget::new(5)),
        Err(FrameEncodeError::FieldBytes {
            field: "principal.identity_path",
            limit: 5
        })
    ));
    Ok(())
}

#[test]
fn all_event_payloads_and_messages_are_checked_before_cloning() -> Result<()> {
    let path = Path::parse("state://a")?;
    for frame in [
        reply(Value::bytes(vec![0; 1025])),
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::StateSet {
                path: path.clone(),
                value: Value::string("x".repeat(1025)),
                source: StateSourceSummary::default(),
            },
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::StateAppend {
                path: path.clone(),
                item: Value::string("x".repeat(1025)),
                source: StateSourceSummary::default(),
            },
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::StateDropPrefixAppend {
                path,
                removed: 2,
                item: Value::string("x".repeat(1025)),
                source: StateSourceSummary::default(),
            },
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::Audit {
                fact: Value::string("x".repeat(1025)),
            },
        },
    ] {
        ensure!(matches!(
            encode_server_frame(&frame, 1024),
            Err(FrameEncodeError::Value(
                ValueEncodeError::InlineBytes { .. }
            ))
        ));
    }
    for frame in [
        ServerFrame::Error {
            id: Some(1),
            failure: crate::ConsoleFailure::new(ConsoleErrorCode::BadRequest, "x".repeat(1025)),
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::SubscriptionClosed {
                reason: "x".repeat(1025),
                failure: None,
            },
        },
    ] {
        ensure!(matches!(
            encode_server_frame(&frame, 1024),
            Err(FrameEncodeError::FieldBytes { .. })
        ));
    }
    Ok(())
}

#[test]
fn prefix_drop_append_keeps_its_count_and_item_on_console_v1_wire() -> Result<()> {
    let path = Path::parse("state://source/window")?;
    let item = Value::integer(9);
    let event = ConsoleEvent::from(xolotl_state::StateEvent::DropPrefixAppend {
        path: path.clone(),
        removed: 3,
        item: item.clone(),
        taint: xolotl_types::TaintSet::author(),
    });
    let bytes = encode_server_frame(&ServerFrame::Event { stream: 7, event }, 4096)?;
    let encoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    let Some(pb::console_frame::Frame::Event(frame)) = encoded.frame else {
        anyhow::bail!("expected event frame")
    };
    ensure!(frame.stream == 7);
    let Some(pb::console_event::Kind::StateDropPrefixAppend(delta)) =
        frame.event.context("console event")?.kind
    else {
        anyhow::bail!("expected prefix drop append")
    };
    ensure!(delta.removed == 3);
    ensure!(xolotl_proto::path_from_pb(&delta.path.context("path")?)? == path);
    ensure!(xolotl_proto::value_from_pb(&delta.item.context("item")?)? == item);
    ensure!(delta.source.context("source")?.author_constant);
    Ok(())
}

#[test]
fn typed_paths_bound_bytes_and_component_allocations() -> Result<()> {
    let path = Path::parse("path://east/state/a/b")?;
    ensure!(ConversionBudget::new(11).path(&path)? == path_to_pb(&path));
    ensure!(matches!(
        ConversionBudget::new(10).path(&path),
        Err(FrameEncodeError::FieldBytes { .. })
    ));

    let frame = ServerFrame::Event {
        stream: 1,
        event: ConsoleEvent::StateDelete {
            path: Path::parse(&format!("state://{}", "a/".repeat(MAX_PATH_SEGMENTS) + "a"))?,
            source: StateSourceSummary::default(),
        },
    };
    ensure!(matches!(
        encode_server_frame(&frame, 16_384),
        Err(FrameEncodeError::PathSegments {
            limit: MAX_PATH_SEGMENTS
        })
    ));
    Ok(())
}

#[test]
fn path_and_value_share_the_inline_budget() -> Result<()> {
    let event = ConsoleEvent::StateSet {
        path: Path::parse("state://a")?,
        value: Value::string("abc".into()),
        source: StateSourceSummary::default(),
    };
    let pb = console_event_to_pb(&event, ConversionBudget::new(9))?;
    ensure!(pb.kind.is_some());
    ensure!(matches!(
        console_event_to_pb(&event, ConversionBudget::new(8)),
        Err(FrameEncodeError::Value(ValueEncodeError::InlineBytes {
            limit: 2
        }))
    ));
    Ok(())
}

#[test]
fn deepest_supported_map_roundtrips_inside_a_real_event() -> Result<()> {
    let path = Path::parse("state://a")?;
    let nested = |depth| {
        (1..depth).fold(Value::integer(i64::MIN), |value, _| {
            Value::map([("key".into(), value)].into_iter().collect())
        })
    };
    let frame = |depth| ServerFrame::Event {
        stream: u64::MAX,
        event: ConsoleEvent::StateSet {
            path: path.clone(),
            value: nested(depth),
            source: StateSourceSummary::default(),
        },
    };
    let bytes = encode_server_frame(&frame(MAX_VALUE_ENCODE_DEPTH), 16_384)?;
    let decoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    ensure!(matches!(
        decoded.frame,
        Some(pb::console_frame::Frame::Event(_))
    ));
    ensure!(matches!(
        encode_server_frame(&frame(MAX_VALUE_ENCODE_DEPTH + 1), 16_384),
        Err(FrameEncodeError::Value(ValueEncodeError::Depth {
            limit: MAX_VALUE_ENCODE_DEPTH
        }))
    ));
    Ok(())
}

#[test]
fn codec_uses_the_adapters_explicit_byte_limit() -> Result<()> {
    const PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
    let frame = reply(Value::bytes(vec![0; PAYLOAD_BYTES]));
    let encoded = encode_server_frame(&frame, PAYLOAD_BYTES + 1024)?;
    ensure!(encoded.len() > PAYLOAD_BYTES);
    ensure!(matches!(
        encode_server_frame(&frame, PAYLOAD_BYTES - 1),
        Err(FrameEncodeError::Value(ValueEncodeError::InlineBytes { limit }))
            if limit == PAYLOAD_BYTES - 1
    ));
    Ok(())
}
