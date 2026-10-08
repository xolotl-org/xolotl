use crate::{Shared, staging::StagingUse, storage};
use std::fs::File;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use tokio::sync::OwnedSemaphorePermit;
use xolotl_state::StateResult;

#[derive(Clone)]
pub(crate) struct Sender {
    queue: mpsc::Sender<Work>,
    staging_use: Arc<StagingUse>,
    undelivered: Arc<Undelivered>,
}

#[derive(Default)]
struct Undelivered(parking_lot::Mutex<Vec<Work>>);

impl Drop for Undelivered {
    fn drop(&mut self) {
        for work in self.0.get_mut().drain(..) {
            work.task.finish();
        }
    }
}

struct Work {
    task: Task,
    _staging_use: Arc<StagingUse>,
}

pub(crate) struct Task {
    pub(crate) file: Option<File>,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) slot: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    pub(crate) probe: Arc<crate::tests::IoProbe>,
}

impl Task {
    fn attempt(&mut self) -> bool {
        #[cfg(test)]
        let _gate = self.probe.cleanup_gate.lock();
        drop(self.file.take());
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            self.probe.cleanup_attempts.fetch_add(1, Ordering::Relaxed);
            if self
                .probe
                .cleanup_failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return false;
            }
        }
        let removed = match std::fs::remove_dir_all(self.directory.path()) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
        if removed {
            drop(self.slot.take());
        }
        removed
    }

    fn finish(mut self) {
        if !self.attempt() {
            let _path = self.directory.keep();
        }
    }
}

struct Pending {
    work: Work,
    next: Instant,
    delay: Duration,
}

fn run(receiver: mpsc::Receiver<Work>) {
    let mut pending: Vec<Pending> = Vec::new();
    loop {
        let received = if let Some(next) = pending.iter().map(|item| item.next).min() {
            receiver.recv_timeout(next.saturating_duration_since(Instant::now()))
        } else {
            receiver
                .recv()
                .map_err(|_disconnected| mpsc::RecvTimeoutError::Disconnected)
        };
        match received {
            Ok(mut work) => {
                if !work.task.attempt() {
                    let delay = Duration::from_millis(100);
                    pending.push(Pending {
                        work,
                        next: Instant::now() + delay,
                        delay,
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                for item in pending {
                    item.work.task.finish();
                }
                return;
            }
        }
        let now = Instant::now();
        let mut index = 0;
        while index < pending.len() {
            if pending[index].next > now {
                index += 1;
                continue;
            }
            if pending[index].work.task.attempt() {
                pending.swap_remove(index);
            } else {
                let item = &mut pending[index];
                item.delay = (item.delay * 2).min(Duration::from_secs(5));
                item.next = Instant::now() + item.delay;
                index += 1;
            }
        }
    }
}

impl Sender {
    pub(crate) fn enqueue(&self, task: Task) {
        let work = Work {
            task,
            _staging_use: Arc::clone(&self.staging_use),
        };
        if let Err(error) = self.queue.send(work) {
            self.undelivered.0.lock().push(error.0);
        }
    }
}

pub(crate) fn start(shared: &Shared) -> StateResult<Sender> {
    let (sender, receiver) = mpsc::channel::<Work>();
    let staging_use: Arc<StagingUse> = Arc::clone(&shared._staging_use);
    #[cfg(test)]
    let probe = Arc::clone(&shared.probe);
    let _worker = std::thread::Builder::new()
        .name("xolotl-object-cleanup".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            run(receiver);
            #[cfg(test)]
            probe
                .cleanup_exits
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        })
        .map_err(storage::io_error)?;
    Ok(Sender {
        queue: sender,
        staging_use,
        undelivered: Arc::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileObjectOptions, FileObjectStore};
    use anyhow::ensure;
    use std::num::NonZeroUsize;
    use std::sync::atomic::Ordering;

    #[test]
    fn failed_handoff_cannot_release_live_capacity() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let store = FileObjectStore::with_options(
            root.path(),
            FileObjectOptions {
                max_uploads: NonZeroUsize::MIN,
                ..FileObjectOptions::default()
            },
        )?;
        let (queue, receiver) = mpsc::channel();
        drop(receiver);
        let sender = Sender {
            queue,
            staging_use: Arc::clone(&store.shared._staging_use),
            undelivered: Arc::default(),
        };
        let directory = tempfile::Builder::new()
            .prefix("upload-")
            .tempdir_in(root.path().join("staging"))?;
        let path = directory.path().to_owned();
        sender.enqueue(Task {
            file: None,
            directory,
            slot: Some(Arc::clone(&store.shared.upload_slots).try_acquire_owned()?),
            probe: Arc::clone(&store.shared.probe),
        });
        ensure!(path.exists() && store.shared.upload_slots.available_permits() == 0);
        store
            .shared
            .probe
            .cleanup_failures
            .store(1, Ordering::Relaxed);
        drop(store);
        let other = FileObjectStore::open(root.path())?;
        ensure!(path.exists());
        drop(other);
        drop(sender);
        ensure!(path.exists());
        let reopened = FileObjectStore::open(root.path())?;
        ensure!(!path.exists());
        drop(reopened);
        Ok(())
    }
}
