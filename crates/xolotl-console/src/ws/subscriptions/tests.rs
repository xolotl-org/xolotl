use super::*;
use anyhow::{Context, ensure};
use xolotl_console_protocol::pb;
use xolotl_types::{Path, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn project(value: u64) -> Result<Option<ConsoleEvent>, String> {
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

#[tokio::test]
async fn state_lag_and_source_close_reclaim_slots() -> anyhow::Result<()> {
    for lagged in [false, true] {
        let mut subscriptions = Subscriptions::new(&ConsoleWsConfig::default());
        let (source, receiver) = broadcast::channel(1);
        subscriptions
            .replace(7, receiver, state_event, "state", deadline())
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
async fn queued_events_retain_their_byte_permits_during_delivery() -> anyhow::Result<()> {
    let config = ConsoleWsConfig::default();
    let mut subscriptions = Subscriptions::new(&config);
    let (source, receiver) = broadcast::channel(1);
    let expires = deadline();
    subscriptions
        .replace(1, receiver, project, "test", expires)
        .await?;
    source.send(42)?;
    let event = receive(&mut subscriptions).await?;
    ensure!(event.deadline == Some(expires));
    ensure!(
        subscriptions.budget.available_permits() + event.bytes.len()
            == config.max_pending_event_bytes
    );
    let pb::console_event::Kind::Fact(fact) = decode(&event)? else {
        anyhow::bail!("expected projected event");
    };
    ensure!(
        xolotl_proto::value_from_pb_checked(&fact.fact.context("fact projection")?)?
            == Value::string("42".into())
    );
    drop(event);
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
        .replace(1, receiver, project, "test", deadline())
        .await?;
    for value in 0..=EVENT_CAPACITY as u64 {
        source.send(value)?;
    }
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.event_rx.len() == EVENT_CAPACITY);
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
        )
        .await?;
    source.send(())?;
    source.send(())?;
    finish_one(&mut subscriptions).await?;
    ensure!(subscriptions.event_rx.len() == 1);
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
                        Err("bounded projection failed".into())
                    } else {
                        Ok(Some(ConsoleEvent::Audit {
                            fact: Value::string("x".repeat(2048)),
                        }))
                    }
                },
                "test",
                deadline(),
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
        .replace(7, receiver, project, "test", deadline())
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
        .replace(7, receiver, project, "test", deadline())
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
        xolotl_proto::value_from_pb_checked(&fact.fact.context("fact projection")?)?
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
        .replace(7, receiver, project, "test", Instant::now())
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
    subscriptions
        .event_tx
        .try_send(QueuedEvent {
            producer,
            bytes,
            budget,
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
            .replace(1, receiver, project, "test", deadline())
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
