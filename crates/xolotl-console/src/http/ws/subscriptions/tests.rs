use super::*;
use anyhow::{Context, ensure};
use xolotl_console_protocol::pb;
use xolotl_types::{Path, TaintSet, TaintSource, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn project(value: u64) -> Result<Option<ConsoleEvent>, &'static str> {
    Ok(Some(ConsoleEvent::Audit {
        fact: Value::string(value.to_string()),
    }))
}

fn decode(event: &SubscriptionEvent) -> anyhow::Result<pb::console_event::Kind> {
    let frame = wire::decode_server_frame(&event.bytes).map_err(anyhow::Error::msg)?;
    let Some(pb::console_frame::Frame::Event(frame)) = frame.frame else {
        anyhow::bail!("expected subscription event frame");
    };
    ensure!(frame.stream == event.stream);
    frame
        .event
        .and_then(|event| event.kind)
        .context("event kind")
}

async fn receive(subscriptions: &mut Subscriptions) -> anyhow::Result<SubscriptionEvent> {
    Ok(tokio::time::timeout(Duration::from_secs(1), subscriptions.next()).await??)
}

async fn closed(subscriptions: &mut Subscriptions) -> anyhow::Result<String> {
    let event = receive(subscriptions).await?;
    ensure!(event.budget.is_none() && event.deadline.is_none());
    ensure!(event.entry.num_permits() == 1);
    let pb::console_event::Kind::Closed(closed) = decode(&event)? else {
        anyhow::bail!("expected subscription closure");
    };
    Ok(closed.reason)
}

async fn finish_one(subscriptions: &mut Subscriptions) -> anyhow::Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        subscriptions.tasks.join_next_with_id(),
    )
    .await?
    .context("subscription task completion")?;
    subscriptions.completed(result);
    Ok(())
}

async fn wait_for_queued(subscriptions: &Subscriptions, count: usize) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while subscriptions.event_rx.len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn enqueue_event(subscriptions: &Subscriptions, stream: u64, value: u64) -> anyhow::Result<()> {
    let producer = subscriptions
        .active
        .get(&stream)
        .context("active producer")?
        .producer;
    let bytes = wire::encode_server_frame(
        &ServerFrame::Event {
            stream,
            event: project(value)
                .map_err(anyhow::Error::msg)?
                .context("projected event")?,
        },
        subscriptions.max_frame_bytes,
    )?;
    let entry = subscriptions.entries.clone().try_acquire_owned()?;
    let budget = subscriptions
        .budget
        .clone()
        .try_acquire_many_owned(u32::try_from(bytes.len())?)?;
    subscriptions
        .event_tx
        .try_send(QueuedEvent {
            producer,
            bytes,
            budget,
            entry,
        })
        .map_err(|_error| anyhow::anyhow!("event queue slot"))?;
    Ok(())
}

fn event_value(event: &SubscriptionEvent) -> anyhow::Result<Value> {
    let pb::console_event::Kind::Fact(fact) = decode(event)? else {
        anyhow::bail!("expected fact event");
    };
    Ok(xolotl_proto::value_from_pb(
        &fact.fact.context("fact value")?,
    )?)
}

#[tokio::test]
async fn stop_releases_queued_budget_before_replacement_without_next_and_keeps_other_stream_order()
-> anyhow::Result<()> {
    let config = ConsoleWsConfig {
        max_pending_event_bytes: MIN_WS_MAX_PENDING_EVENT_BYTES,
        ..ConsoleWsConfig::default()
    };
    let mut subscriptions = Subscriptions::new(&config);
    let (other, receiver) = broadcast::channel(4);
    subscriptions
        .replace(9, receiver, project, "test", deadline(), None)
        .await?;
    let (previous, receiver) = broadcast::channel(1);
    let large = |_: ()| {
        Ok(Some(ConsoleEvent::Audit {
            fact: Value::string("x".repeat(9000)),
        }))
    };
    subscriptions
        .replace(7, receiver, large, "test", deadline(), None)
        .await?;
    other.send(1)?;
    let first = tokio::time::timeout(Duration::from_secs(1), subscriptions.event_rx.recv())
        .await?
        .context("first other-stream event")?;
    subscriptions.retained.push_back(first);
    previous.send(())?;
    wait_for_queued(&subscriptions, 1).await?;
    let cancelled = subscriptions
        .event_rx
        .try_recv()
        .context("cancelled retained event")?;
    subscriptions.retained.push_back(cancelled);
    enqueue_event(&subscriptions, 7, 99)?;
    other.send(2)?;
    wait_for_queued(&subscriptions, 2).await?;
    ensure!(subscriptions.budget.available_permits() < 9000);

    subscriptions.stop(7).await?;
    ensure!(previous.receiver_count() == 0);
    ensure!(subscriptions.event_rx.is_empty());
    ensure!(subscriptions.retained.len() == 2);
    ensure!(
        subscriptions
            .retained
            .iter()
            .all(|event| event.producer.stream == 9)
    );
    let retained_bytes: usize = subscriptions
        .retained
        .iter()
        .map(|event| event.bytes.len())
        .sum();
    ensure!(
        subscriptions.budget.available_permits() + retained_bytes == config.max_pending_event_bytes
    );
    ensure!(
        subscriptions.entries.available_permits() + subscriptions.retained.len() == EVENT_CAPACITY
    );

    let (replacement, receiver) = broadcast::channel(1);
    subscriptions
        .replace(7, receiver, large, "test", deadline(), None)
        .await?;
    replacement.send(())?;
    wait_for_queued(&subscriptions, 1).await?;
    other.send(3)?;
    wait_for_queued(&subscriptions, 2).await?;
    for (stream, value) in [
        (9, Value::string("1".into())),
        (9, Value::string("2".into())),
        (7, Value::string("x".repeat(9000))),
        (9, Value::string("3".into())),
    ] {
        let event = receive(&mut subscriptions).await?;
        ensure!(event.stream == stream);
        ensure!(event_value(&event)? == value);
        ensure!(event.entry.num_permits() == 1);
    }
    ensure!(subscriptions.contains(7) && subscriptions.contains(9));
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY);
    subscriptions.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn retained_channel_and_inflight_frames_share_the_existing_entry_bound() -> anyhow::Result<()>
{
    let config = ConsoleWsConfig::default();
    let mut subscriptions = Subscriptions::new(&config);
    let (_previous, receiver) = broadcast::channel::<u64>(1);
    subscriptions
        .replace(1, receiver, project, "test", deadline(), None)
        .await?;
    let (_other, receiver) = broadcast::channel::<u64>(1);
    subscriptions
        .replace(2, receiver, project, "test", deadline(), None)
        .await?;
    for value in 0..EVENT_CAPACITY {
        enqueue_event(
            &subscriptions,
            if value % 2 == 0 { 1 } else { 2 },
            value as u64,
        )?;
    }
    let inflight = receive(&mut subscriptions).await?;
    ensure!(inflight.stream == 1);
    subscriptions.stop(1).await?;
    ensure!(subscriptions.retained.len() == EVENT_CAPACITY / 2);
    ensure!(subscriptions.event_rx.is_empty());
    for value in 0..EVENT_CAPACITY / 2 - 1 {
        enqueue_event(&subscriptions, 2, value as u64)?;
    }
    ensure!(subscriptions.entries.available_permits() == 0);
    ensure!(subscriptions.entries.clone().try_acquire_owned().is_err());
    ensure!(subscriptions.retained.len() + subscriptions.event_rx.len() + 1 == EVENT_CAPACITY);
    subscriptions.queue_completion(Completion {
        producer: Producer {
            stream: 3,
            generation: 1,
        },
        reason: Some("subscription completed".into()),
        sent: 0,
        drain_queued: true,
        failure: None,
        delivery: None,
    });
    let other_inflight = receive(&mut subscriptions).await?;
    ensure!(other_inflight.stream == 2);
    ensure!(event_value(&other_inflight)? == Value::string("1".into()));
    ensure!(subscriptions.retained.len() + subscriptions.event_rx.len() + 2 == EVENT_CAPACITY);
    drop(other_inflight);
    let terminal = receive(&mut subscriptions).await?;
    ensure!(terminal.stream == 3 && terminal.budget.is_none());
    ensure!(matches!(
        decode(&terminal)?,
        pb::console_event::Kind::Closed(_)
    ));
    ensure!(subscriptions.entries.available_permits() == 0);
    ensure!(subscriptions.retained.len() + subscriptions.event_rx.len() + 2 == EVENT_CAPACITY);
    drop(terminal);
    drop(inflight);
    subscriptions.shutdown().await;
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY);
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    Ok(())
}

#[tokio::test]
async fn state_lag_and_source_close_reclaim_slots() -> anyhow::Result<()> {
    for lagged in [false, true] {
        let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
        let (source, receiver) = broadcast::channel(1);
        subscriptions
            .replace(7, receiver, state_event, "state", deadline(), None)
            .await?;
        if lagged {
            let event = StateEvent::Delete {
                path: Path::parse("state://kernel/test")?,
                taint: xolotl_types::TaintSet::pristine(),
            };
            source.send(event.clone())?;
            source.send(event)?;
        }
        drop(source);
        let reason = closed(&mut subscriptions).await?;
        ensure!(reason.contains(if lagged { "lagged" } else { "source closed" }));
        ensure!(subscriptions.len() == 0 && subscriptions.tasks.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn state_watch_wire_events_include_only_source_categories() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let (sender, receiver) = broadcast::channel(4);
    subscriptions
        .replace(7, receiver, state_event, "state", deadline(), None)
        .await?;
    let path = Path::parse("state://example/visible")?;
    let private_path = "state://vault/private-lineage-path";
    let taint = TaintSet::from_recorded_sources(vec![
        TaintSource::AuthorConstant,
        TaintSource::ModelOutput,
        TaintSource::Inbound {
            source: "private-ingress-source".into(),
            channel: "private-ingress-channel".into(),
        },
        TaintSource::Fetched {
            host: "private-fetch-host".into(),
        },
        TaintSource::Protected {
            path: Path::parse(private_path)?,
        },
    ]);
    let events = [
        StateEvent::Set {
            path: path.clone(),
            value: Value::integer(1),
            taint: taint.clone(),
        },
        StateEvent::Append {
            path: path.clone(),
            item: Value::integer(2),
            taint: taint.clone(),
        },
        StateEvent::DropPrefixAppend {
            path: path.clone(),
            removed: 1,
            item: Value::integer(3),
            taint: taint.clone(),
        },
        StateEvent::Delete { path, taint },
    ];
    for (index, event) in events.into_iter().enumerate() {
        sender.send(event)?;
        let wire_event = receive(&mut subscriptions).await?;
        let source = match (index, decode(&wire_event)?) {
            (0, pb::console_event::Kind::StateSet(event)) => event.source,
            (1, pb::console_event::Kind::StateAppend(event)) => event.source,
            (2, pb::console_event::Kind::StateDropPrefixAppend(event)) => {
                ensure!(event.removed == 1);
                event.source
            }
            (3, pb::console_event::Kind::StateDelete(event)) => event.source,
            _ => anyhow::bail!("unexpected State watch event kind"),
        }
        .context("source summary")?;
        ensure!(
            source
                == pb::StateSourceSummary {
                    tainted: true,
                    author_constant: true,
                    model_output: true,
                    inbound: true,
                    fetched: true,
                    protected: true,
                }
        );
        for private in [
            private_path,
            "private-ingress-source",
            "private-ingress-channel",
            "private-fetch-host",
        ] {
            ensure!(
                !wire_event
                    .bytes
                    .windows(private.len())
                    .any(|window| window == private.as_bytes()),
                "private lineage label was encoded"
            );
        }
    }
    Ok(())
}

struct Finite(Vec<u64>);

impl NotificationSource for Finite {
    type Event = u64;
    fn into_events(self) -> impl Stream<Item = Result<u64, SourceError>> + Send {
        stream::iter(self.0.into_iter().map(Ok))
    }
}

#[tokio::test]
async fn terminal_service_failure_preserves_execution_and_audit_receipt() -> anyhow::Result<()> {
    struct Rejected(crate::ConsoleFailure);
    impl NotificationSource for Rejected {
        type Event = u64;
        fn into_events(self) -> impl Stream<Item = Result<u64, SourceError>> + Send {
            stream::iter([Err(SourceError::Rejected(self.0))])
        }
    }
    let mut failure =
        crate::ConsoleFailure::new(crate::ConsoleErrorCode::Conflict, "conflict".into());
    failure.current_version = Some(7);
    failure.execution = Some(Box::new(crate::ExecutionReference {
        execution_id: Some("execution-42".into()),
        process_id: "42".into(),
        program_id: "ab".repeat(32),
    }));
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    subscriptions
        .replace(7, Rejected(failure), project, "runtime", deadline(), None)
        .await?;
    let event = receive(&mut subscriptions).await?;
    let pb::console_event::Kind::Closed(closed) = decode(&event)? else {
        anyhow::bail!("expected closure");
    };
    ensure!(closed.reason == "subscription failed");
    let failure = closed.failure.context("structured failure")?;
    ensure!(failure.code == pb::ConsoleErrorCode::VersionConflict as i32);
    ensure!(failure.current_version == Some(7));
    ensure!(failure.execution.context("execution")?.process_id == "42");
    Ok(())
}

#[tokio::test]
async fn source_failure_uses_a_public_category() -> anyhow::Result<()> {
    struct Failed;
    impl NotificationSource for Failed {
        type Event = u64;
        fn into_events(self) -> impl Stream<Item = Result<u64, SourceError>> + Send {
            stream::iter([Err(SourceError::Failed)])
        }
    }

    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    subscriptions
        .replace(7, Failed, project, "state", deadline(), None)
        .await?;
    ensure!(
        closed(&mut subscriptions).await?
            == "state notification failed; resynchronize and subscribe again"
    );
    ensure!(subscriptions.len() == 0);
    Ok(())
}

#[tokio::test]
async fn terminal_service_failure_follows_queued_events() -> anyhow::Result<()> {
    struct RejectedAfterData(crate::ConsoleFailure);
    impl NotificationSource for RejectedAfterData {
        type Event = u64;
        fn into_events(self) -> impl Stream<Item = Result<u64, SourceError>> + Send {
            stream::iter([Ok(1), Ok(2), Err(SourceError::Rejected(self.0))])
        }
    }

    let failure = crate::ConsoleFailure::new(crate::ConsoleErrorCode::Conflict, "conflict".into());
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    subscriptions
        .replace(
            7,
            RejectedAfterData(failure),
            project,
            "runtime",
            deadline(),
            None,
        )
        .await?;
    // Exercise the ordering when the worker finishes before transport delivery.
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.len() == 1);
    for expected in [1, 2] {
        let event = receive(&mut subscriptions).await?;
        let pb::console_event::Kind::Fact(fact) = decode(&event)? else {
            anyhow::bail!("queued event was lost before terminal failure")
        };
        ensure!(
            xolotl_proto::value_from_pb(&fact.fact.context("value")?)?
                == Value::string(expected.to_string())
        );
    }
    let event = receive(&mut subscriptions).await?;
    let pb::console_event::Kind::Closed(closed) = decode(&event)? else {
        anyhow::bail!("expected terminal failure")
    };
    ensure!(
        closed.failure.context("structured failure")?.code
            == pb::ConsoleErrorCode::VersionConflict as i32
    );
    ensure!(subscriptions.len() == 0);
    Ok(())
}

#[tokio::test]
async fn normal_completion_drains_all_queued_events_before_closure() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    subscriptions
        .replace(
            7,
            Finite(vec![1, 2, 3]),
            project,
            "finite",
            deadline(),
            None,
        )
        .await?;
    // Force the producer to finish before the transport consumes its first event.
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.len() == 1);
    for expected in [1, 2, 3] {
        let event = receive(&mut subscriptions).await?;
        let pb::console_event::Kind::Fact(fact) = decode(&event)? else {
            anyhow::bail!("queued event was lost")
        };
        ensure!(
            xolotl_proto::value_from_pb(&fact.fact.context("value")?)?
                == Value::string(expected.to_string())
        );
    }
    ensure!(closed(&mut subscriptions).await? == "subscription completed");
    ensure!(subscriptions.len() == 0);
    Ok(())
}

#[tokio::test]
async fn completed_producer_cannot_deliver_queued_events_after_visibility_expiry()
-> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    subscriptions
        .replace(
            7,
            Finite(vec![1, 2, 3]),
            project,
            "finite",
            deadline(),
            None,
        )
        .await?;
    finish_one(&mut subscriptions).await?;
    subscriptions.active.get_mut(&7).context("active")?.deadline = Instant::now();
    ensure!(closed(&mut subscriptions).await?.contains("expired"));
    ensure!(subscriptions.len() == 0);
    subscriptions.shutdown().await;
    ensure!(
        subscriptions.budget.available_permits()
            == ConsoleWsConfig::default().max_pending_event_bytes
    );
    Ok(())
}

#[tokio::test]
async fn queued_events_retain_their_byte_permits_during_delivery() -> anyhow::Result<()> {
    let config = ConsoleWsConfig::default();
    let mut subscriptions = Subscriptions::new(&config);
    let (source, receiver) = broadcast::channel(1);
    let expires = deadline();
    subscriptions
        .replace(1, receiver, project, "test", expires, None)
        .await?;
    source.send(42)?;
    let event = receive(&mut subscriptions).await?;
    ensure!(event.deadline == Some(expires));
    ensure!(event.entry.num_permits() == 1);
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY - 1);
    ensure!(
        subscriptions.budget.available_permits() + event.bytes.len()
            == config.max_pending_event_bytes
    );
    let pb::console_event::Kind::Fact(fact) = decode(&event)? else {
        anyhow::bail!("expected projected event");
    };
    ensure!(
        xolotl_proto::value_from_pb(&fact.fact.context("fact projection")?)?
            == Value::string("42".into())
    );
    drop(event);
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY);
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    subscriptions.stop(1).await?;
    ensure!(subscriptions.tasks.is_empty() && source.receiver_count() == 0);
    Ok(())
}

#[tokio::test]
async fn queue_saturation_closes_without_waiting_for_data_delivery() -> anyhow::Result<()> {
    let config = ConsoleWsConfig::default();
    let mut subscriptions = Subscriptions::new(&config);
    let (source, receiver) = broadcast::channel(1024);
    subscriptions
        .replace(1, receiver, project, "test", deadline(), None)
        .await?;
    for value in 0..=EVENT_CAPACITY as u64 {
        source.send(value)?;
    }
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.event_rx.is_empty() && subscriptions.retained.is_empty());
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY);
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    ensure!(subscriptions.len() == 0);
    ensure!(closed(&mut subscriptions).await?.contains("queue"));
    subscriptions.shutdown().await;
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    Ok(())
}

#[tokio::test]
async fn byte_saturation_closes_independently_of_the_data_queue() -> anyhow::Result<()> {
    let config = ConsoleWsConfig {
        max_pending_event_bytes: MIN_WS_MAX_PENDING_EVENT_BYTES,
        ..ConsoleWsConfig::default()
    };
    let mut subscriptions = Subscriptions::new(&config);
    let (source, receiver) = broadcast::channel(4);
    subscriptions
        .replace(
            1,
            receiver,
            |_: ()| {
                Ok(Some(ConsoleEvent::Audit {
                    fact: Value::string("x".repeat(9000)),
                }))
            },
            "test",
            deadline(),
            None,
        )
        .await?;
    source.send(())?;
    source.send(())?;
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.event_rx.is_empty() && subscriptions.retained.is_empty());
    ensure!(subscriptions.entries.available_permits() == EVENT_CAPACITY);
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    ensure!(subscriptions.len() == 0);
    ensure!(closed(&mut subscriptions).await?.contains("byte budget"));
    subscriptions.shutdown().await;
    ensure!(subscriptions.budget.available_permits() == config.max_pending_event_bytes);
    Ok(())
}

#[tokio::test]
async fn projection_and_encoding_failures_close_the_subscription() -> anyhow::Result<()> {
    let config = ConsoleWsConfig {
        max_frame_bytes: 1024,
        ..ConsoleWsConfig::default()
    };
    for projection_fails in [true, false] {
        let mut subscriptions = Subscriptions::new(&config);
        let (source, receiver) = broadcast::channel(1);
        subscriptions
            .replace(
                1,
                receiver,
                move |_: ()| {
                    if projection_fails {
                        Err("bounded projection failed")
                    } else {
                        Ok(Some(ConsoleEvent::Audit {
                            fact: Value::string("x".repeat(2048)),
                        }))
                    }
                },
                "test",
                deadline(),
                None,
            )
            .await?;
        source.send(())?;
        let reason = closed(&mut subscriptions).await?;
        ensure!(reason.contains(if projection_fails {
            "projection failed"
        } else {
            "encoded"
        }));
        ensure!(subscriptions.len() == 0);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic,
    clippy::panic_in_result_fn,
    reason = "intentional worker panic exercises subscription cleanup"
)]
async fn worker_panic_reclaims_its_slot_and_notifies_the_client() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let (source, receiver) = broadcast::channel(1);
    subscriptions
        .replace(
            1,
            receiver,
            |_: ()| panic!("projection panic"),
            "test",
            deadline(),
            None,
        )
        .await?;
    source.send(())?;
    ensure!(
        closed(&mut subscriptions)
            .await?
            .contains("stopped unexpectedly")
    );
    ensure!(subscriptions.len() == 0 && subscriptions.tasks.is_empty());
    ensure!(source.receiver_count() == 0);
    Ok(())
}

#[tokio::test]
async fn replacement_rejects_queued_events_and_closures_from_older_generations()
-> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let (previous, receiver) = broadcast::channel(2);
    subscriptions
        .replace(7, receiver, project, "test", deadline(), None)
        .await?;
    previous.send(1)?;
    let stale = tokio::time::timeout(Duration::from_secs(1), subscriptions.event_rx.recv())
        .await?
        .context("old queued event")?;
    drop(previous);
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.pending.len() == 1);

    let (replacement, receiver) = broadcast::channel(1);
    subscriptions
        .replace(7, receiver, project, "test", deadline(), None)
        .await?;
    subscriptions
        .event_tx
        .try_send(stale)
        .map_err(|_error| anyhow::anyhow!("stale event queue slot"))?;
    replacement.send(2)?;
    let event = receive(&mut subscriptions).await?;
    let pb::console_event::Kind::Fact(fact) = decode(&event)? else {
        anyhow::bail!("old closure removed the replacement");
    };
    ensure!(
        xolotl_proto::value_from_pb(&fact.fact.context("fact projection")?)?
            == Value::string("2".into())
    );
    ensure!(subscriptions.contains(7) && subscriptions.pending.is_empty());
    subscriptions.stop(7).await?;
    Ok(())
}

#[tokio::test]
async fn expired_subscription_discards_already_queued_events() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let (_source, receiver) = broadcast::channel(1);
    subscriptions
        .replace(7, receiver, project, "test", Instant::now(), None)
        .await?;
    let producer = subscriptions
        .active
        .get(&7)
        .context("active subscription")?
        .producer;
    let bytes = wire::encode_server_frame(
        &ServerFrame::Event {
            stream: 7,
            event: ConsoleEvent::Audit {
                fact: Value::string("expired".into()),
            },
        },
        subscriptions.max_frame_bytes,
    )?;
    let budget = subscriptions
        .budget
        .clone()
        .try_acquire_many_owned(u32::try_from(bytes.len())?)?;
    let entry = subscriptions.entries.clone().try_acquire_owned()?;
    subscriptions
        .event_tx
        .try_send(QueuedEvent {
            producer,
            bytes,
            budget,
            entry,
        })
        .map_err(|_error| anyhow::anyhow!("expired event queue slot"))?;
    ensure!(closed(&mut subscriptions).await? == "subscription visibility expired");
    ensure!(subscriptions.len() == 0);
    subscriptions.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn quiet_subscriptions_close_when_their_visibility_expires() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let (_source, receiver) = broadcast::channel(1);
    subscriptions
        .replace(
            1,
            receiver,
            project,
            "test",
            Instant::now() + Duration::from_millis(5),
            None,
        )
        .await?;
    ensure!(closed(&mut subscriptions).await? == "subscription visibility expired");
    Ok(())
}

#[tokio::test]
async fn cancelling_the_owner_aborts_all_subscription_workers() -> anyhow::Result<()> {
    let (source, receiver) = broadcast::channel(1);
    let (ready, started) = oneshot::channel();
    let owner = tokio::spawn(async move {
        let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
        subscriptions
            .replace(1, receiver, project, "test", deadline(), None)
            .await?;
        ready.send(()).map_err(|_error| ShutdownError)?;
        std::future::pending::<()>().await;
        Ok::<(), ShutdownError>(())
    });
    started.await?;
    owner.abort();
    ensure!(owner.await.err().context("cancelled owner")?.is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), async {
        while source.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn cancelling_a_stop_does_not_detach_the_worker() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    let producer = Producer {
        stream: 1,
        generation: 1,
    };
    let (cancel, cancelled) = oneshot::channel();
    let (waiting, observed) = oneshot::channel();
    let (alive, released) = oneshot::channel::<()>();
    let abort = subscriptions.tasks.spawn(async move {
        let _alive = alive;
        let _cancelled = cancelled.await;
        let _sent = waiting.send(());
        std::future::pending::<Completion>().await
    });
    subscriptions.active.insert(
        1,
        Subscription {
            delivered: 0,
            completion: None,
            delivery: None,
            producer,
            cancel,
            abort,
            deadline: deadline(),
        },
    );
    let owner = tokio::spawn(async move { subscriptions.stop(1).await });
    observed.await?;
    owner.abort();
    ensure!(
        owner
            .await
            .err()
            .context("cancelled subscription stop")?
            .is_cancelled()
    );
    ensure!(
        tokio::time::timeout(Duration::from_secs(1), released)
            .await?
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_uses_one_deadline_for_all_unresponsive_workers() -> anyhow::Result<()> {
    let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
    for stream in 1..=4 {
        let producer = Producer {
            stream,
            generation: stream,
        };
        let (cancel, receiver) = oneshot::channel();
        let abort = subscriptions.tasks.spawn(async move {
            let _cancelled = receiver.await;
            std::future::pending::<Completion>().await
        });
        subscriptions.active.insert(
            stream,
            Subscription {
                delivered: 0,
                completion: None,
                delivery: None,
                producer,
                cancel,
                abort,
                deadline: deadline(),
            },
        );
    }
    tokio::time::timeout(Duration::from_millis(700), subscriptions.shutdown()).await?;
    ensure!(subscriptions.tasks.is_empty() && subscriptions.len() == 0);
    ensure!(!subscriptions.failed());
    Ok(())
}

#[test]
fn pending_byte_budget_is_clamped_without_allocating_the_entire_budget() {
    for (configured, expected) in [
        (0, MIN_WS_MAX_PENDING_EVENT_BYTES),
        (usize::MAX, HARD_MAX_WS_PENDING_EVENT_BYTES),
    ] {
        let config = ConsoleWsConfig {
            max_pending_event_bytes: configured,
            ..ConsoleWsConfig::default()
        };
        let subscriptions = Subscriptions::new(&config);
        assert_eq!(subscriptions.budget.available_permits(), expected);
    }
}
