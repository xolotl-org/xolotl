use super::*;
use std::{
    future::{Ready, ready},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use xolotl_state::{
    StateEvent, StateRead, StateResult, StateStream, StateWatch, host::WatchRegistry,
};
use xolotl_types::TaintSource;

#[derive(Default)]
struct Observations {
    events: WatchRegistry,
    current: parking_lot::Mutex<xolotl_state::StateObservation>,
    race: AtomicBool,
}

impl Observations {
    fn publish(&self, event: StateEvent) -> StateResult<()> {
        {
            let mut current = self.current.lock();
            xolotl_state::apply_history_event(&mut current, &event)?;
        }
        for sender in self.events.matching(event.path()) {
            drop(sender.send(event.clone()));
        }
        Ok(())
    }
}

impl StateRead for Observations {
    type Read<'a> = Ready<StateResult<xolotl_state::StateObservation>>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        let current = self.current.lock().clone();
        if self.race.swap(false, Ordering::SeqCst)
            && let Err(error) = self.publish(StateEvent::Set {
                path: path.clone(),
                value: Value::bytes(vec![0, 255]),
                taint: TaintSet::of(TaintSource::ModelOutput),
            })
        {
            return ready(Err(error));
        }
        ready(Ok(current))
    }
}

impl StateWatch for Observations {
    type Subscription = StateStream;
    type Subscribe<'a> = Ready<StateResult<StateStream>>;
    fn subscribe<'a>(&'a self, path: &'a Path) -> Self::Subscribe<'a> {
        ready(
            self.events
                .subscribe(path.clone(), NonZeroUsize::MIN.saturating_add(1)),
        )
    }
}

fn fixture() -> anyhow::Result<(Arc<Observations>, StateDriver, DriverContext, Path)> {
    let port = Arc::new(Observations::default());
    let backend = Backend::new()
        .with_read(port.clone())
        .with_watch(port.clone())
        .with_signal(port.clone());
    let path = Path::parse("state://signal/ready")?;
    let ctx =
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_target_path(path.clone());
    Ok((port, StateDriver::new(backend), ctx, path))
}

#[tokio::test]
async fn subscription_precedes_snapshot_and_owns_its_registration() -> anyhow::Result<()> {
    let (port, driver, ctx, _) = fixture()?;
    port.race.store(true, Ordering::SeqCst);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        driver.call(MethodId::new(6), Value::null(), OutputMode::Unary, &ctx),
    )
    .await??;
    ensure!(output.outcome == Outcome::Done(Value::bytes(vec![0, 255])));
    ensure!(output.taint == TaintSet::of(TaintSource::ModelOutput));
    ensure!(port.events.is_empty());
    *port.current.lock() = Default::default();
    let mut pending =
        Box::pin(driver.call(MethodId::new(6), Value::null(), OutputMode::Unary, &ctx));
    ensure!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    ensure!(port.events.len() == 1);
    drop(pending);
    ensure!(port.events.is_empty());
    Ok(())
}

#[tokio::test]
async fn deletion_control_sources_survive_later_values_and_lag() -> anyhow::Result<()> {
    for lag in [false, true] {
        let (port, driver, ctx, path) = fixture()?;
        let initial = TaintSet::of(TaintSource::ModelOutput);
        *port.current.lock() = xolotl_state::StateObservation {
            value: None,
            taint: initial.clone(),
        };
        let mut pending =
            Box::pin(driver.call(MethodId::new(6), Value::null(), OutputMode::Unary, &ctx));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
        port.publish(StateEvent::Set {
            path: path.clone(),
            value: Value::null(),
            taint: TaintSet::pristine(),
        })?;
        port.publish(StateEvent::Delete {
            path: path.clone(),
            taint: taint.clone(),
        })?;
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        for value in 0..if lag { 3 } else { 1 } {
            port.publish(StateEvent::Append {
                path: path.clone(),
                item: Value::integer(value),
                taint: TaintSet::pristine(),
            })?;
        }
        let output = pending.await?;
        ensure!(output.taint == initial.merged(&taint));
        ensure!(matches!(output.outcome, Outcome::Fail(_)) == lag);
        if !lag {
            ensure!(output.outcome == Outcome::Done(Value::list(vec![Value::integer(0)])));
        }
        ensure!(port.events.is_empty());
    }
    Ok(())
}
