//! Bounded channels with explicit backpressure and terminal states.

/// Sending never silently drops a value. Ownership is returned on rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendError<T> {
    /// No buffer slot is available; retry after the consumer makes progress.
    Full(T),
    /// The stream is terminal and cannot accept another item.
    Closed(T),
}

/// A stream yields its terminal result after all buffered values are consumed.
#[derive(Debug, Eq, PartialEq)]
pub enum Receive<T, E> {
    /// Next buffered value in producer order.
    Item(T),
    /// No item is ready, but the stream remains open.
    Pending,
    /// Stable terminal result, returned only after draining buffered items.
    End(Result<(), E>),
}

/// Single-owner channel backed by caller-provided slots. Thread synchronization,
/// wakeups and durable logging belong to the host adapter.
pub struct Channel<'a, T, E> {
    slots: &'a mut [Option<T>],
    head: usize,
    len: usize,
    end: Option<Result<(), E>>,
}

impl<'a, T, E: Clone> Channel<'a, T, E> {
    /// Clear and attach fixed-capacity slots.
    pub fn new(slots: &'a mut [Option<T>]) -> Self {
        slots.fill_with(|| None);
        Self {
            slots,
            head: 0,
            len: 0,
            end: None,
        }
    }
    /// Enqueue a value without blocking, allocating, or dropping on overflow.
    pub fn try_send(&mut self, value: T) -> Result<(), SendError<T>> {
        if self.end.is_some() {
            return Err(SendError::Closed(value));
        }
        if self.len == self.slots.len() {
            return Err(SendError::Full(value));
        }
        self.slots[(self.head + self.len) % self.slots.len()] = Some(value);
        self.len += 1;
        Ok(())
    }
    /// Consume the next item or inspect the stream's readiness.
    pub fn receive(&mut self) -> Receive<T, E> {
        if self.len > 0 {
            let value = self.slots[self.head].take();
            self.head = (self.head + 1) % self.slots.len();
            self.len -= 1;
            if let Some(value) = value {
                return Receive::Item(value);
            }
        }
        match &self.end {
            Some(end) => Receive::End(end.clone()),
            None => Receive::Pending,
        }
    }
    /// Closing is idempotent; the first terminal result wins.
    pub fn close(&mut self, result: Result<(), E>) {
        if self.end.is_none() {
            self.end = Some(result);
        }
    }
    /// Number of buffered items.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether the buffer currently contains no items.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Maximum number of items the supplied storage can hold.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}
