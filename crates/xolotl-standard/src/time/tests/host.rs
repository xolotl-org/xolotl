use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context as TaskContext, Poll, Wake, Waker};
use std::time::{Duration, Instant};
use xolotl_kernel::host::{HostClock, HostRuntime, TaskSpawner};

struct ControlledClock {
    origin: Instant,
    elapsed: AtomicU64,
    wall: AtomicI64,
    next_wait: AtomicUsize,
    created: AtomicUsize,
    cancelled: AtomicUsize,
    waits: parking_lot::Mutex<BTreeMap<usize, (Instant, Waker)>>,
}

impl ControlledClock {
    fn at(now: i64) -> Arc<Self> {
        Self::at_origin(now, Instant::now())
    }

    fn at_origin(now: i64, origin: Instant) -> Arc<Self> {
        Arc::new(Self {
            origin,
            elapsed: AtomicU64::new(0),
            wall: AtomicI64::new(now),
            next_wait: AtomicUsize::new(0),
            created: AtomicUsize::new(0),
            cancelled: AtomicUsize::new(0),
            waits: parking_lot::Mutex::new(BTreeMap::new()),
        })
    }

    fn advance(&self, elapsed: u64) {
        self.elapsed.store(elapsed, Ordering::SeqCst);
        let wakers: Vec<_> = self
            .waits
            .lock()
            .values()
            .filter(|(deadline, _waker)| *deadline <= self.monotonic_now())
            .map(|(_deadline, waker)| waker.clone())
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }

    fn runtime(self: &Arc<Self>) -> HostRuntime {
        struct Tasks(HostRuntime);

        impl TaskSpawner for Tasks {
            fn spawn(
                &self,
                future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
            ) -> std::result::Result<
                Arc<dyn xolotl_kernel::host::AbortTask>,
                xolotl_kernel::host::TaskSpawnError,
            > {
                self.0.spawn(future)
            }
        }

        HostRuntime::new(
            self.clone(),
            Arc::new(Tasks(HostRuntime::tokio())),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        )
    }
}

impl HostClock for ControlledClock {
    fn monotonic_now(&self) -> Instant {
        self.origin + Duration::from_millis(self.elapsed.load(Ordering::SeqCst))
    }

    fn unix_millis(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.created.fetch_add(1, Ordering::SeqCst);
        Box::pin(Wait {
            clock: self,
            deadline,
            wait_id: None,
        })
    }
}

struct Wait<'clock> {
    clock: &'clock ControlledClock,
    deadline: Instant,
    wait_id: Option<usize>,
}

impl Future for Wait<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<()> {
        if self.clock.monotonic_now() >= self.deadline {
            if let Some(wait_id) = self.wait_id.take() {
                self.clock.waits.lock().remove(&wait_id);
            }
            return Poll::Ready(());
        }
        let wait_id = match self.wait_id {
            Some(wait_id) => wait_id,
            None => {
                let wait_id = self.clock.next_wait.fetch_add(1, Ordering::SeqCst);
                self.wait_id = Some(wait_id);
                wait_id
            }
        };
        self.clock
            .waits
            .lock()
            .insert(wait_id, (self.deadline, context.waker().clone()));
        Poll::Pending
    }
}

impl Drop for Wait<'_> {
    fn drop(&mut self) {
        if let Some(wait_id) = self.wait_id
            && self.clock.waits.lock().remove(&wait_id).is_some()
        {
            self.clock.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn sleep_uses_the_host_monotonic_clock_and_owns_only_its_wait() -> Result<()> {
    let clock = ControlledClock::at(1_000);
    let driver = TimeDriver::new(clock.runtime());
    let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(wakes.clone());
    let mut context = TaskContext::from_waker(&waker);
    let unpolled = driver.call(
        MethodId::new(1),
        Value::integer(10),
        OutputMode::Unary,
        &ctx,
    );
    drop(unpolled);
    ensure!(clock.created.load(Ordering::SeqCst) == 0);
    for input in [
        Value::integer(0),
        Value::map(BTreeMap::from([("millis".into(), Value::integer(0))])),
    ] {
        let mut zero = driver.call(MethodId::new(1), input, OutputMode::Unary, &ctx);
        ensure!(
            matches!(zero.as_mut().poll(&mut context), Poll::Ready(Ok(DriverOutput { outcome: Outcome::Done(value), .. })) if value.is_null())
        );
    }
    ensure!(clock.created.load(Ordering::SeqCst) == 0);
    let mut first = driver.call(
        MethodId::new(1),
        Value::integer(10),
        OutputMode::Unary,
        &ctx,
    );
    let mut second = driver.call(
        MethodId::new(1),
        Value::integer(20),
        OutputMode::Unary,
        &ctx,
    );
    ensure!(first.as_mut().poll(&mut context).is_pending());
    ensure!(second.as_mut().poll(&mut context).is_pending());
    let deadlines: Vec<_> = clock
        .waits
        .lock()
        .values()
        .map(|(deadline, _waker)| *deadline)
        .collect();
    ensure!(
        deadlines
            == [
                clock.origin + Duration::from_millis(10),
                clock.origin + Duration::from_millis(20)
            ]
    );
    clock.wall.store(i64::MAX, Ordering::SeqCst);
    ensure!(first.as_mut().poll(&mut context).is_pending());
    clock.wall.store(i64::MIN, Ordering::SeqCst);
    clock.advance(9);
    ensure!(first.as_mut().poll(&mut context).is_pending());
    ensure!(wakes.0.load(Ordering::SeqCst) == 0);
    drop(first);
    ensure!(clock.cancelled.load(Ordering::SeqCst) == 1 && clock.waits.lock().len() == 1);
    clock.advance(19);
    ensure!(second.as_mut().poll(&mut context).is_pending());
    clock.advance(20);
    ensure!(wakes.0.load(Ordering::SeqCst) == 1);
    ensure!(
        matches!(second.as_mut().poll(&mut context), Poll::Ready(Ok(DriverOutput { outcome: Outcome::Done(value), .. })) if value.is_null())
    );
    ensure!(clock.waits.lock().is_empty() && clock.cancelled.load(Ordering::SeqCst) == 1);
    ensure!(clock.created.load(Ordering::SeqCst) == 2);
    drop(second);
    ensure!(clock.cancelled.load(Ordering::SeqCst) == 1);
    let mut latest = Instant::now();
    for bit in (0..64).rev() {
        if let Some(next) = latest.checked_add(Duration::from_secs(1_u64 << bit)) {
            latest = next;
        }
    }
    for bit in (0..30).rev() {
        if let Some(next) = latest.checked_add(Duration::from_nanos(1_u64 << bit)) {
            latest = next;
        }
    }
    ensure!(latest.checked_add(Duration::from_millis(1)).is_none());
    let bounded_clock = ControlledClock::at_origin(0, latest);
    let bounded_driver = TimeDriver::new(bounded_clock.runtime());
    let mut unrepresentable =
        bounded_driver.call(MethodId::new(1), Value::integer(1), OutputMode::Unary, &ctx);
    ensure!(matches!(
        unrepresentable.as_mut().poll(&mut context),
        Poll::Ready(Err(DriverError::InvalidInput(_)))
    ));
    ensure!(
        bounded_clock.created.load(Ordering::SeqCst) == 0 && bounded_clock.waits.lock().is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn installed_time_observations_use_the_kernel_wall_clock() -> Result<()> {
    use xolotl_graph::{DoNode, OperationTemplate};
    use xolotl_kernel::{Bootstrap, KernelBuilder};
    use xolotl_types::ResourceName;

    let clock = ControlledClock::at(1_234);
    let boot = Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(clock.runtime())
            .build(),
    );
    crate::install_standard(
        &boot,
        &crate::StandardConfig::default()
            .with_modules(crate::StandardModules::none().with(crate::StandardModule::Time)),
    )?;
    let execute = async |effect: &str, input: Value| -> Result<Value> {
        let name = ResourceName::new(xolotl_types::Path::parse(effect)?);
        let handle = boot.open_for(boot.root(), &name, "perform")?;
        let executor = boot.kernel().executor_for(boot.root());
        executor.bind_handle(name.clone(), handle)?;
        match executor
            .eval(&DoNode::Op(OperationTemplate {
                target: name,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(input),
            }))
            .await
            .outcome
        {
            Outcome::Done(value) => Ok(value),
            other => bail!("expected time observation, got {other:?}"),
        }
    };
    for (now, input, interval) in [
        (
            1_234,
            Value::map(BTreeMap::from([
                ("every".into(), Value::integer(5)),
                ("unit".into(), Value::string("m".into())),
            ])),
            300_000,
        ),
        (
            -1_234,
            Value::map(BTreeMap::from([("interval_ms".into(), Value::integer(25))])),
            25,
        ),
        (
            2_000,
            Value::map(BTreeMap::from([("every".into(), Value::integer(2))])),
            2_000,
        ),
    ] {
        clock.wall.store(now, Ordering::SeqCst);
        ensure!(execute("effect://time/now", Value::null()).await? == Value::integer(now));
        let cron = execute("effect://time/cron", input).await?;
        ensure!(
            cron == Value::map(BTreeMap::from([
                ("next_millis".into(), Value::integer(now + interval)),
                ("interval_ms".into(), Value::integer(interval))
            ]))
        );
    }
    ensure!(clock.created.load(Ordering::SeqCst) == 0 && clock.waits.lock().is_empty());
    Ok(())
}

#[tokio::test]
async fn cron_checks_interval_and_deadline_arithmetic_without_wrapping() -> Result<()> {
    let clock = ControlledClock::at(1);
    let driver = TimeDriver::new(clock.runtime());
    let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1));
    for (now, interval, expected) in [
        (1, i64::MAX, None),
        (i64::MAX - 5, 5, Some(i64::MAX)),
        (i64::MIN, 1, Some(i64::MIN + 1)),
    ] {
        clock.wall.store(now, Ordering::SeqCst);
        let input = Value::map(BTreeMap::from([(
            "interval_ms".into(),
            Value::integer(interval),
        )]));
        let result = driver
            .call(MethodId::new(2), input, OutputMode::Unary, &ctx)
            .await;
        match (result, expected) {
            (Err(DriverError::InvalidInput(_)), None) => {}
            (Ok(output), Some(next)) => ensure!(
                output.outcome
                    == Outcome::Done(Value::map(BTreeMap::from([
                        ("next_millis".into(), Value::integer(next)),
                        ("interval_ms".into(), Value::integer(interval))
                    ])))
            ),
            (result, expected) => bail!(
                "incorrect deadline arithmetic at {now} + {interval}: {result:?}, expected {expected:?}"
            ),
        }
    }
    clock.wall.store(0, Ordering::SeqCst);
    let largest_days = i64::MAX / 86_400_000;
    for (every, expected) in [
        (largest_days, Some(largest_days * 86_400_000)),
        (largest_days + 1, None),
    ] {
        let input = Value::map(BTreeMap::from([
            ("every".into(), Value::integer(every)),
            ("unit".into(), Value::string("d".into())),
        ]));
        let result = driver
            .call(MethodId::new(2), input, OutputMode::Unary, &ctx)
            .await;
        match (result, expected) {
            (Err(DriverError::InvalidInput(_)), None) => {}
            (Ok(output), Some(interval)) => ensure!(
                output.outcome
                    == Outcome::Done(Value::map(BTreeMap::from([
                        ("next_millis".into(), Value::integer(interval)),
                        ("interval_ms".into(), Value::integer(interval)),
                    ])))
            ),
            (result, expected) => bail!(
                "incorrect unit arithmetic for {every} days: {result:?}, expected {expected:?}"
            ),
        }
    }
    Ok(())
}
