use std::{
    future::{Future, Ready, ready},
    rc::Rc,
    task::{Context, Poll, Waker},
};
use xolotl_state::{StateRead, StateResult, TaintedValue};
use xolotl_types::{Path, Value};

struct LocalRead(Rc<Value>);

impl StateRead for LocalRead {
    type Read<'a> = Ready<StateResult<Option<TaintedValue>>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        ready(Ok(Some(TaintedValue::pristine((*self.0).clone()))))
    }
}

#[test]
fn static_read_allows_local_ownership_without_a_scheduler() -> anyhow::Result<()> {
    let local = LocalRead(Rc::new(Value::integer(42)));
    let path = Path::parse("state://local")?;
    let mut future = local.read_tainted(&path);
    let Poll::Ready(value) =
        std::pin::Pin::new(&mut future).poll(&mut Context::from_waker(Waker::noop()))
    else {
        anyhow::bail!("local read unexpectedly suspended");
    };
    anyhow::ensure!(value? == Some(TaintedValue::pristine(Value::integer(42))));
    Ok(())
}

#[cfg(feature = "std")]
mod host {
    use super::*;
    use std::sync::Arc;
    use xolotl_state::{Backend, StateError};

    struct ReadOnly;

    impl StateRead for ReadOnly {
        type Read<'a> = Ready<StateResult<Option<TaintedValue>>>;

        fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
            ready(Ok(Some(TaintedValue::pristine(Value::integer(7)))))
        }
    }

    #[tokio::test]
    async fn host_assembles_only_installed_capabilities() -> anyhow::Result<()> {
        let backend = Backend::new().with_read(Arc::new(ReadOnly));
        let path = Path::parse("state://readonly")?;
        anyhow::ensure!(
            backend.has_read()
                && !backend.has_write()
                && !backend.has_query()
                && !backend.has_history()
                && !backend.has_watch()
        );
        anyhow::ensure!(backend.read(&path).await? == Some(Value::integer(7)));
        anyhow::ensure!(matches!(
            backend.write_set(&path, Value::null()).await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("write"),
                ..
            })
        ));
        anyhow::ensure!(matches!(
            backend.query(&xolotl_state::StateScan::new(path)).await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("query"),
                ..
            })
        ));
        Ok(())
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn subscription_reports_lag_and_closure_and_releases_receiver() -> anyhow::Result<()> {
    use xolotl_state::{StateEvent, StateWatchError};
    let path = Path::parse("state://watch")?;
    let (sender, receiver) = tokio::sync::broadcast::channel(1);
    let mut stream = xolotl_state::host::broadcast_stream(receiver);
    for value in 0..2 {
        sender.send(StateEvent::Set {
            path: path.clone(),
            value: Value::integer(value),
            taint: Default::default(),
        })?;
    }
    anyhow::ensure!(matches!(
        stream.recv().await,
        Err(StateWatchError::Lagged(1))
    ));
    anyhow::ensure!(matches!(
        stream.recv().await?,
        StateEvent::Set { value, .. } if value.as_int() == Some(1)
    ));
    let other = xolotl_state::host::broadcast_stream(sender.subscribe());
    anyhow::ensure!(sender.receiver_count() == 2);
    drop(other);
    anyhow::ensure!(sender.receiver_count() == 1);
    drop(sender);
    anyhow::ensure!(matches!(stream.recv().await, Err(StateWatchError::Closed)));
    Ok(())
}
