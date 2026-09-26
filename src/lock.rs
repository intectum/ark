//! Advisory locks on entries, reached by account path.
//!
//! A directory takes its metadata where it stands rather than through a
//! rename, so a reader has to be held off while it is replaced. These are what
//! does that. They exclude only callers that take the lock themselves, and
//! only on the one host.

use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;

use crate::storage::to_fs_path;
use crate::types::Context;

/// An advisory lock on an entry, held until it is dropped.
///
/// Released by the kernel if the process holding it dies, so it is never left
/// stale. It excludes only callers that take the lock themselves — it says
/// nothing about anything else on the host touching the same entry.
#[must_use = "the lock is released as soon as it is dropped"]
pub struct Lock {
    _file: fs::File,
}

/// Take a shared lock on `path`, waiting for an exclusive holder to release.
///
/// Any number of shared holders hold it at once. See [`Lock`].
pub fn lock_shared(ctx: &Context, path: &str) -> io::Result<Lock> {
    lock(ctx, path, libc::LOCK_SH)
}

/// Take an exclusive lock on `path`, waiting for every other holder to
/// release.
///
/// See [`Lock`].
pub fn lock_exclusive(ctx: &Context, path: &str) -> io::Result<Lock> {
    lock(ctx, path, libc::LOCK_EX)
}

// Locking an entry a second time waits on the first lock even within the one
// process, so a caller holds at most one at a time and never takes one across
// a call that may take another.
fn lock(ctx: &Context, path: &str, operation: i32) -> io::Result<Lock> {
    let file = fs::File::open(to_fs_path(ctx, path)?)?;

    // The descriptor belongs to `file`, which outlives the call, and the
    // operation is one of the two constants above.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Lock { _file: file })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    use crate::storage::create_dir;
    use crate::testing::fs::{TEST_ADDRESS, account_context, create_test_account, in_test_dir};

    // How long a holder stays in the critical section, and how long a thread
    // waiting on something that should already have happened gives it before
    // calling it a failure.
    const HELD_FOR: Duration = Duration::from_micros(200);
    const PATIENCE: Duration = Duration::from_secs(2);

    // Locking rests on flock working against a directory descriptor, which
    // these check directly. The metadata tests that depend on it race two
    // threads and could pass by luck on a platform where the lock is quietly
    // doing nothing; these cannot.

    fn locked_directory(temp_dir: &std::path::Path) -> Context {
        let (_, _, account_dir) = create_test_account(temp_dir, TEST_ADDRESS);
        let (context, _) = account_context(&account_dir);
        create_dir(&context, "/dir").unwrap();

        context
    }

    #[test]
    fn a_directory_can_be_locked_on_this_platform() {
        in_test_dir("ark_lock_test", |temp_dir| {
            let context = locked_directory(temp_dir);

            // Reported rather than unwrapped: on a platform that refuses a
            // lock on a directory, the OS error is the whole diagnosis.
            if let Err(error) = lock_exclusive(&context, "/dir") {
                panic!("this platform will not lock a directory: {}", error);
            }
            if let Err(error) = lock_shared(&context, "/dir") {
                panic!("this platform will not take a shared lock on a directory: {}", error);
            }
        });
    }

    #[test]
    fn an_exclusive_lock_blocks_until_the_one_before_it_is_dropped() {
        in_test_dir("ark_lock_test", |temp_dir| {
            let context = Arc::new(locked_directory(temp_dir));
            let held = lock_exclusive(&context, "/dir").unwrap();
            let taken = Arc::new(AtomicBool::new(false));

            let waiter = thread::spawn({
                let (context, taken) = (Arc::clone(&context), Arc::clone(&taken));
                move || {
                    let _lock = lock_exclusive(&context, "/dir").unwrap();
                    taken.store(true, Ordering::SeqCst);
                }
            });

            thread::sleep(Duration::from_millis(50));
            assert!(!taken.load(Ordering::SeqCst), "a second exclusive lock was granted while the first was held");

            drop(held);
            waiter.join().unwrap();
            assert!(taken.load(Ordering::SeqCst), "the lock was not released when it was dropped");
        });
    }

    #[test]
    fn an_exclusive_lock_lets_one_holder_in_at_a_time() {
        in_test_dir("ark_lock_test", |temp_dir| {
            let context = Arc::new(locked_directory(temp_dir));
            let inside = Arc::new(AtomicBool::new(false));

            let holders: Vec<_> = (0..4).map(|_| {
                let (context, inside) = (Arc::clone(&context), Arc::clone(&inside));
                thread::spawn(move || {
                    for _ in 0..25 {
                        let _lock = lock_exclusive(&context, "/dir").unwrap();

                        assert!(!inside.swap(true, Ordering::SeqCst), "two holders were inside at once");
                        thread::sleep(HELD_FOR);
                        assert!(inside.swap(false, Ordering::SeqCst), "another holder came and went while this one held the lock");
                    }
                })
            }).collect();

            for holder in holders {
                holder.join().unwrap();
            }
        });
    }

    #[test]
    fn a_shared_lock_and_an_exclusive_one_keep_each_other_out() {
        in_test_dir("ark_lock_test", |temp_dir| {
            let context = Arc::new(locked_directory(temp_dir));
            let readers = Arc::new(AtomicUsize::new(0));
            let writing = Arc::new(AtomicBool::new(false));

            let mut threads = Vec::new();

            for _ in 0..2 {
                let (context, readers, writing) = (Arc::clone(&context), Arc::clone(&readers), Arc::clone(&writing));
                threads.push(thread::spawn(move || {
                    for _ in 0..25 {
                        let _lock = lock_exclusive(&context, "/dir").unwrap();

                        writing.store(true, Ordering::SeqCst);
                        assert_eq!(readers.load(Ordering::SeqCst), 0, "a reader held the entry while it was being written");
                        thread::sleep(HELD_FOR);
                        assert_eq!(readers.load(Ordering::SeqCst), 0, "a reader took the entry while it was being written");
                        writing.store(false, Ordering::SeqCst);
                    }
                }));
            }

            for _ in 0..2 {
                let (context, readers, writing) = (Arc::clone(&context), Arc::clone(&readers), Arc::clone(&writing));
                threads.push(thread::spawn(move || {
                    for _ in 0..25 {
                        let _lock = lock_shared(&context, "/dir").unwrap();

                        readers.fetch_add(1, Ordering::SeqCst);
                        assert!(!writing.load(Ordering::SeqCst), "the entry was being written while a reader held it");
                        thread::sleep(HELD_FOR);
                        assert!(!writing.load(Ordering::SeqCst), "a write started while a reader held the entry");
                        readers.fetch_sub(1, Ordering::SeqCst);
                    }
                }));
            }

            for thread in threads {
                thread.join().unwrap();
            }
        });
    }

    #[test]
    fn shared_locks_do_not_keep_each_other_out() {
        in_test_dir("ark_lock_test", |temp_dir| {
            let context = Arc::new(locked_directory(temp_dir));
            let holders = Arc::new(AtomicUsize::new(0));

            // Each waits for the other to be holding the entry at the same
            // time. A lock that is exclusive when it should be shared leaves
            // one of them waiting, rather than deadlocking the test.
            let readers: Vec<_> = (0..2).map(|_| {
                let (context, holders) = (Arc::clone(&context), Arc::clone(&holders));
                thread::spawn(move || {
                    let _lock = lock_shared(&context, "/dir").unwrap();
                    holders.fetch_add(1, Ordering::SeqCst);

                    let deadline = Instant::now() + PATIENCE;
                    while holders.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                        thread::yield_now();
                    }

                    holders.load(Ordering::SeqCst)
                })
            }).collect();

            for reader in readers {
                assert_eq!(reader.join().unwrap(), 2, "two shared locks were not held at the same time");
            }
        });
    }
}
