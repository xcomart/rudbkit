//! Keyed, single-flight acquisition of shared resources.
//!
//! The pool stores weak references: callers own each resource, and releasing
//! the last caller destroys it. Replacing a dead resource cannot affect leases
//! on either generation. A per-key lock serializes creation without blocking
//! connections to other targets.
//!
//! # Callbacks run under the key's lock
//!
//! [`LeasePool::acquire`] calls `usable` and `create` while it holds that key's
//! lock — that is what makes acquisition single-flight — and the lock is not
//! reentrant. A callback must therefore never acquire the same key from the
//! same pool, directly or through anything it calls: that thread would wait on
//! itself forever. Debug builds turn that hang into a panic. Acquiring a
//! *different* key from a callback works, but two callbacks doing it to each
//! other's keys on two threads deadlock just the same, and no check catches
//! that; keep `create` to opening the resource.

#[cfg(debug_assertions)]
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;

type Slot<V> = Arc<Mutex<Weak<V>>>;

/// Weakly cached resources, with independent acquisition locks for each key.
///
/// The callbacks given to [`acquire`](Self::acquire) run while that key's lock
/// is held and must not re-enter the pool for the same key — see the module
/// documentation. [`live_count`](Self::live_count) is safe to call from
/// anywhere, callbacks included.
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
    ///
    /// `usable` is asked about the cached resource, if one is still alive, and
    /// `create` runs when there is none or `usable` turned it down. Both run
    /// with this key's lock held, so another thread acquiring the same key
    /// waits for them; that is the single flight. They must not call
    /// `acquire` for the same key on this pool, which would deadlock the
    /// calling thread (debug builds panic instead). For the same reason a
    /// resource that `usable` rejects may be dropped under the lock, if every
    /// other owner let go in the meantime, so `V`'s `Drop` must not re-enter
    /// for its own key either.
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
        // Declared before the guard so that it is released after it.
        #[cfg(debug_assertions)]
        let _held = HeldSlot::enter(Arc::as_ptr(&slot) as usize);
        let mut cached = slot.lock();
        if let Some(value) = cached.upgrade().filter(|value| usable(value)) {
            return Ok(value);
        }
        let value = Arc::new(create()?);
        *cached = Arc::downgrade(&value);
        Ok(value)
    }

    /// Counts cached resources still owned by at least one caller.
    ///
    /// Never waits on a key's lock, so it may be called from `acquire`'s
    /// callbacks; a key being created right then is not counted.
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

#[cfg(debug_assertions)]
thread_local! {
    /// Addresses of the slots whose lock this thread holds inside `acquire`.
    static HELD_SLOTS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Debug-only record that this thread is inside `acquire` for one slot, so a
/// callback that re-enters for the same key panics instead of hanging.
///
/// A slot's address identifies its key for as long as it is recorded: the
/// `Arc` behind it is kept alive by `acquire` until the record is dropped.
#[cfg(debug_assertions)]
struct HeldSlot(usize);

#[cfg(debug_assertions)]
impl HeldSlot {
    fn enter(slot: usize) -> Self {
        let reentered = HELD_SLOTS.with_borrow_mut(|held| {
            let reentered = held.contains(&slot);
            if !reentered {
                held.push(slot);
            }
            reentered
        });
        assert!(
            !reentered,
            "LeasePool::acquire re-entered for a key whose callback is running on this \
             thread; this deadlocks in release builds"
        );
        HeldSlot(slot)
    }
}

#[cfg(debug_assertions)]
impl Drop for HeldSlot {
    fn drop(&mut self) {
        HELD_SLOTS.with_borrow_mut(|held| {
            if let Some(index) = held.iter().rposition(|&slot| slot == self.0) {
                held.swap_remove(index);
            }
        });
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

    #[test]
    fn a_callback_may_acquire_another_key_and_count() {
        let pool = LeasePool::new();
        let outer = pool
            .acquire(
                1,
                |_| true,
                || {
                    assert_eq!(pool.live_count(), 0);
                    let inner = pool.acquire(2, |_| true, || Ok::<_, ()>(2)).unwrap();
                    assert_eq!(pool.live_count(), 1);
                    Ok::<_, ()>(*inner + 1)
                },
            )
            .unwrap();
        assert_eq!(*outer, 3);
        // The inner lease was dropped inside the callback; only the outer one
        // is left, and the same key can be acquired again afterwards.
        assert_eq!(pool.live_count(), 1);
        assert!(Arc::ptr_eq(
            &outer,
            &pool.acquire(1, |_| true, || Ok::<_, ()>(0)).unwrap()
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "LeasePool::acquire re-entered")]
    fn re_entering_the_same_key_panics_in_debug_builds() {
        let pool = LeasePool::new();
        let _ = pool.acquire(
            1,
            |_| true,
            || {
                pool.acquire(1, |_| true, || Ok::<_, ()>(0))
                    .map(|value| *value)
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn a_panicking_re_entry_leaves_the_key_usable() {
        let pool = LeasePool::new();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.acquire(
                1,
                |_| true,
                || {
                    pool.acquire(1, |_| true, || Ok::<_, ()>(0))
                        .map(|value| *value)
                },
            )
        }));
        assert!(attempt.is_err());
        assert_eq!(*pool.acquire(1, |_| true, || Ok::<_, ()>(7)).unwrap(), 7);
    }
}
