//! Keyed, single-flight acquisition of shared resources.
//!
//! The pool stores weak references: callers own each resource, and releasing
//! the last caller destroys it. Replacing a dead resource cannot affect leases
//! on either generation. A per-key lock serializes creation without blocking
//! connections to other targets.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;

type Slot<V> = Arc<Mutex<Weak<V>>>;

/// Weakly cached resources, with independent acquisition locks for each key.
pub struct LeasePool<K, V> {
    slots: Mutex<Option<HashMap<K, Slot<V>>>>,
}

impl<K, V> Default for LeasePool<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LeasePool<K, V> {
    /// Creates an empty pool without allocating.
    pub const fn new() -> Self {
        Self {
            slots: Mutex::new(None),
        }
    }
}

impl<K: Eq + Hash, V> LeasePool<K, V> {
    /// Reuses a live resource or creates one while serializing this key only.
    pub fn acquire<E>(
        &self,
        key: K,
        usable: impl FnOnce(&V) -> bool,
        create: impl FnOnce() -> Result<V, E>,
    ) -> Result<Arc<V>, E> {
        let slot = {
            let mut slots = self.slots.lock();
            let slots = slots.get_or_insert_with(HashMap::new);
            slots.retain(|_, slot| {
                Arc::strong_count(slot) > 1
                    || slot.try_lock().is_none_or(|value| value.strong_count() > 0)
            });
            Arc::clone(
                slots
                    .entry(key)
                    .or_insert_with(|| Arc::new(Mutex::new(Weak::new()))),
            )
        };
        let mut cached = slot.lock();
        if let Some(value) = cached.upgrade().filter(|value| usable(value)) {
            return Ok(value);
        }
        let value = Arc::new(create()?);
        *cached = Arc::downgrade(&value);
        Ok(value)
    }

    /// Counts cached resources still owned by at least one caller.
    pub fn live_count(&self) -> usize {
        self.slots.lock().as_ref().map_or(0, |slots| {
            slots
                .values()
                .filter(|slot| {
                    slot.try_lock()
                        .is_some_and(|value| value.strong_count() > 0)
                })
                .count()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct Resource {
        alive: AtomicBool,
        closed: Arc<AtomicUsize>,
    }

    impl Resource {
        fn new(closed: &Arc<AtomicUsize>) -> Self {
            Self {
                alive: AtomicBool::new(true),
                closed: Arc::clone(closed),
            }
        }
        fn usable(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
    }

    impl Drop for Resource {
        fn drop(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn an_old_lease_cannot_close_its_replacement() {
        let pool = LeasePool::new();
        let old_closed = Arc::new(AtomicUsize::new(0));
        let new_closed = Arc::new(AtomicUsize::new(0));
        let old = pool
            .acquire(1, Resource::usable, || {
                Ok::<_, ()>(Resource::new(&old_closed))
            })
            .unwrap();
        old.alive.store(false, Ordering::SeqCst);
        let new = pool
            .acquire(1, Resource::usable, || {
                Ok::<_, ()>(Resource::new(&new_closed))
            })
            .unwrap();
        drop(old);
        assert_eq!(old_closed.load(Ordering::SeqCst), 1);
        assert_eq!(new_closed.load(Ordering::SeqCst), 0);
        assert_eq!(pool.live_count(), 1);
        drop(new);
        assert_eq!(new_closed.load(Ordering::SeqCst), 1);
        assert_eq!(pool.live_count(), 0);
    }

    #[test]
    fn simultaneous_acquisitions_open_once_and_share_until_the_last_owner() {
        let pool = LeasePool::new();
        let starts = AtomicUsize::new(0);
        let closed = Arc::new(AtomicUsize::new(0));
        let barrier = Barrier::new(8);
        let owners = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        pool.acquire(1, Resource::usable, || {
                            starts.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, ()>(Resource::new(&closed))
                        })
                        .unwrap()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(owners.iter().all(|value| Arc::ptr_eq(value, &owners[0])));
        assert_eq!(closed.load(Ordering::SeqCst), 0);
        drop(owners);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unrelated_keys_can_open_at_the_same_time() {
        let pool = LeasePool::new();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let workers: Vec<_> = [1, 2]
                .into_iter()
                .map(|key| {
                    scope.spawn({
                        let pool = &pool;
                        let barrier = &barrier;
                        move || {
                            pool.acquire(
                                key,
                                |_| true,
                                || {
                                    barrier.wait();
                                    Ok::<_, ()>(key)
                                },
                            )
                            .unwrap()
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        });
    }

    #[test]
    fn a_failed_open_can_be_retried() {
        let pool = LeasePool::new();
        assert_eq!(
            pool.acquire(1, |_| true, || Err::<u8, _>("failed")),
            Err("failed")
        );
        assert_eq!(*pool.acquire(1, |_| true, || Ok::<_, ()>(42)).unwrap(), 42);
    }
}
