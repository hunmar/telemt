use super::*;
use crate::stats::Stats;
use dashmap::DashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use tokio::io::ReadBuf;
use tokio::time::{Duration, Instant};

#[derive(Default)]
struct WakeCounter {
    wakes: AtomicUsize,
}

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

fn saturate_quota_user_locks() -> Vec<Arc<std::sync::Mutex<()>>> {
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("quota-retry-backoff-saturate-{idx}")));
    }
    retained
}

#[tokio::test]
async fn positive_uncontended_writer_keeps_retry_wakes_zero() {
    let _guard = quota_test_guard();

    let stats = Arc::new(Stats::new());
    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        "quota-backoff-positive".to_string(),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x41, 0x42]);
    assert!(poll.is_ready(), "uncontended writer must complete immediately");
    assert_eq!(
        wake_counter.wakes.load(Ordering::Relaxed),
        0,
        "uncontended path must not schedule deferred contention wakes"
    );
}

#[tokio::test]
async fn adversarial_writer_sustained_contention_executor_repoll_is_rate_limited() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = "quota-backoff-adversarial-writer";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before polling writer");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        user.to_string(),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0xAA]);
    assert!(first.is_pending());

    let start = Instant::now();
    let mut observed = 0usize;
    while start.elapsed() < Duration::from_millis(80) {
        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > observed {
            observed = wakes;
            let pending = Pin::new(&mut io).poll_write(&mut cx, &[0xAB]);
            assert!(pending.is_pending());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert!(
        wake_counter.wakes.load(Ordering::Relaxed) <= 16,
        "sustained contention must be rate limited; observed wakes={} in 80ms",
        wake_counter.wakes.load(Ordering::Relaxed)
    );

    drop(held_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0xAC]);
    assert!(ready.is_ready());
}

#[tokio::test]
async fn adversarial_reader_sustained_contention_executor_repoll_is_rate_limited() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = "quota-backoff-adversarial-reader";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before polling reader");

    let mut io = StatsIo::new(
        tokio::io::empty(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        user.to_string(),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0u8; 1];

    let mut buf = ReadBuf::new(&mut storage);
    let first = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
    assert!(first.is_pending());

    let start = Instant::now();
    let mut observed = 0usize;
    while start.elapsed() < Duration::from_millis(80) {
        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > observed {
            observed = wakes;
            let mut next = ReadBuf::new(&mut storage);
            let pending = Pin::new(&mut io).poll_read(&mut cx, &mut next);
            assert!(pending.is_pending());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert!(
        wake_counter.wakes.load(Ordering::Relaxed) <= 16,
        "sustained contention must be rate limited; observed wakes={} in 80ms",
        wake_counter.wakes.load(Ordering::Relaxed)
    );

    drop(held_guard);
    let mut done = ReadBuf::new(&mut storage);
    let ready = Pin::new(&mut io).poll_read(&mut cx, &mut done);
    assert!(ready.is_ready());
}

#[tokio::test]
async fn edge_backoff_attempt_resets_after_contention_release() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = "quota-backoff-edge-reset";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before polling writer");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        user.to_string(),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let initial = Pin::new(&mut io).poll_write(&mut cx, &[0x31]);
    assert!(initial.is_pending());

    tokio::time::sleep(Duration::from_millis(15)).await;
    let wakes = wake_counter.wakes.load(Ordering::Relaxed);
    if wakes > 0 {
        let pending = Pin::new(&mut io).poll_write(&mut cx, &[0x32]);
        assert!(pending.is_pending());
    }

    drop(held_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0x33]);
    assert!(ready.is_ready());
    assert!(
        !io.quota_write_wake_scheduled,
        "successful write must clear deferred wake scheduling flag"
    );
    assert!(
        io.quota_write_retry_sleep.is_none(),
        "successful write must clear deferred sleep slot"
    );
}

#[tokio::test]
async fn light_fuzz_writer_repoll_schedule_keeps_wake_budget_bounded() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = "quota-backoff-fuzz-writer";
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before fuzz loop");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        user.to_string(),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let mut seed = 0x5EED_CAFE_7788_9900u64;
    for _ in 0..64 {
        let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x51]);
        assert!(poll.is_pending());

        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let sleep_ms = (seed % 4) as u64;
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    assert!(
        wake_counter.wakes.load(Ordering::Relaxed) <= 24,
        "fuzzed repoll schedule must keep wake budget bounded; observed wakes={}",
        wake_counter.wakes.load(Ordering::Relaxed)
    );

    drop(held_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_multi_waiter_contention_keeps_global_wake_budget_bounded() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = format!("quota-backoff-stress-{}", std::process::id());
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before launching stress waiters");

    let waiters = 48usize;
    let mut ios = Vec::with_capacity(waiters);
    let mut wake_counters = Vec::with_capacity(waiters);

    for _ in 0..waiters {
        ios.push(StatsIo::new(
            tokio::io::sink(),
            Arc::new(SharedCounters::new()),
            Arc::clone(&stats),
            user.clone(),
            Some(4096),
            Arc::new(AtomicBool::new(false)),
            tokio::time::Instant::now(),
        ));
    }

    for io in &mut ios {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);
        let pending = Pin::new(io).poll_write(&mut cx, &[0x61]);
        assert!(pending.is_pending());
        wake_counters.push(counter);
    }

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(120) {
        for (idx, counter) in wake_counters.iter().enumerate() {
            if counter.wakes.load(Ordering::Relaxed) > 0 {
                let waker = Waker::from(Arc::clone(counter));
                let mut cx = Context::from_waker(&waker);
                let pending = Pin::new(&mut ios[idx]).poll_write(&mut cx, &[0x62]);
                assert!(pending.is_pending());
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let total_wakes: usize = wake_counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    assert!(
        total_wakes <= waiters * 20,
        "stress contention must keep aggregate wake budget bounded; waiters={waiters}, wakes={total_wakes}"
    );

    drop(held_guard);
}
