use std::fmt;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

const WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCount(NonZeroUsize);

impl ThreadCount {
    pub const ONE: Self = Self(NonZeroUsize::MIN);

    #[must_use]
    pub fn new(count: usize) -> Option<Self> {
        NonZeroUsize::new(count).map(Self)
    }

    #[must_use]
    pub fn get(self) -> usize {
        self.0.get()
    }
}

#[derive(Debug)]
pub enum ThreadsError {
    CannotStart(std::io::Error),
    WorkerPanicked,
}

impl fmt::Display for ThreadsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotStart(error) => write!(formatter, "cannot start a thread: {error}"),
            Self::WorkerPanicked => write!(formatter, "a worker thread panicked"),
        }
    }
}

impl std::error::Error for ThreadsError {}

pub fn each_in_parallel<T, R>(
    items: &[T],
    threads: ThreadCount,
    work: impl Fn(&T) -> R + Sync,
) -> Result<Vec<R>, ThreadsError>
where
    T: Sync,
    R: Send,
{
    let workers = threads.get().min(items.len());
    if workers <= 1 {
        return Ok(items.iter().map(work).collect());
    }
    let next_item = AtomicUsize::new(0);
    let take_items = || {
        let mut done = Vec::new();
        loop {
            let index = next_item.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(index) else {
                return done;
            };
            done.push((index, work(item)));
        }
    };
    let mut indexed = thread::scope(|scope| {
        let mut running = Vec::with_capacity(workers);
        for _ in 0..workers {
            let worker = thread::Builder::new()
                .stack_size(WORKER_STACK_BYTES)
                .spawn_scoped(scope, take_items)
                .map_err(ThreadsError::CannotStart)?;
            running.push(worker);
        }
        let mut indexed = Vec::with_capacity(items.len());
        for worker in running {
            indexed.extend(worker.join().map_err(|_| ThreadsError::WorkerPanicked)?);
        }
        Ok(indexed)
    })?;
    indexed.sort_unstable_by_key(|(index, _)| *index);
    Ok(indexed.into_iter().map(|(_, result)| result).collect())
}
