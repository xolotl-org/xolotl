use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Embedding-selected scheduling at the end of a bounded execution quantum.
pub trait Cooperate {
    /// No `Send`, allocator, or timer is required by the scheduler boundary.
    type Yield<'a>: Future<Output = ()> + Unpin
    where
        Self: 'a;

    /// Give another task or an interrupt-driven executor an opportunity to run.
    fn cooperate(&self) -> Self::Yield<'_>;
}

/// A scheduler-independent wake that yields once to the embedding's executor.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cooperative;

impl Cooperate for Cooperative {
    type Yield<'a> = YieldOnce;

    fn cooperate(&self) -> YieldOnce {
        YieldOnce(false)
    }
}

/// Concrete allocation-free future returned by [`Cooperative`].
pub struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
