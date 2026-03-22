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
        retained.push(quota_user_lock(&format!("quota-retry-bench-saturate-{idx}")));
    }
    retained
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_contention_wake_rate_decays_with_backoff_curve() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = format!("quota-backoff-bench-{}", std::process::id());
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before benchmark run");

    let waiters = 64usize;
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
        let pending = Pin::new(io).poll_write(&mut cx, &[0x71]);
        assert!(pending.is_pending());
        wake_counters.push(counter);
    }

    let mut observed = vec![0usize; waiters];
    let start = Instant::now();
    let mut wakes_at_40ms = 0usize;
    let mut wakes_at_160ms = 0usize;

    while start.elapsed() < Duration::from_millis(200) {
        for (idx, counter) in wake_counters.iter().enumerate() {
            let wakes = counter.wakes.load(Ordering::Relaxed);
            if wakes > observed[idx] {
                observed[idx] = wakes;
                let waker = Waker::from(Arc::clone(counter));
                let mut cx = Context::from_waker(&waker);
                let pending = Pin::new(&mut ios[idx]).poll_write(&mut cx, &[0x72]);
                assert!(pending.is_pending());
            }
        }

        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(40) && wakes_at_40ms == 0 {
            wakes_at_40ms = wake_counters
                .iter()
                .map(|counter| counter.wakes.load(Ordering::Relaxed))
                .sum();
        }
        if elapsed >= Duration::from_millis(160) && wakes_at_160ms == 0 {
            wakes_at_160ms = wake_counters
                .iter()
                .map(|counter| counter.wakes.load(Ordering::Relaxed))
                .sum();
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let total_wakes: usize = wake_counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    let wakes_at_200ms = total_wakes;
    let early_window_wakes = wakes_at_40ms;
    let late_window_wakes = wakes_at_200ms.saturating_sub(wakes_at_160ms);

    assert!(
        total_wakes <= waiters * 28,
        "backoff benchmark exceeded wake budget; waiters={waiters}, wakes={total_wakes}"
    );

    assert!(
        early_window_wakes > 0,
        "benchmark failed to observe early contention wakes"
    );

    assert!(
        late_window_wakes * 4 <= early_window_wakes * 3,
        "wake-rate decay invariant violated; early_0_40ms={early_window_wakes}, late_160_200ms={late_window_wakes}, total={total_wakes}"
    );

    drop(held_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_read_contention_wake_rate_decays_with_backoff_curve() {
    let _guard = quota_test_guard();

    let _retained = saturate_quota_user_locks();
    let user = format!("quota-backoff-read-bench-{}", std::process::id());
    let stats = Arc::new(Stats::new());

    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold quota lock before read benchmark run");

    let waiters = 64usize;
    let mut ios = Vec::with_capacity(waiters);
    let mut wake_counters = Vec::with_capacity(waiters);

    for _ in 0..waiters {
        ios.push(StatsIo::new(
            tokio::io::empty(),
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
        let mut storage = [0u8; 1];
        let mut buf = ReadBuf::new(&mut storage);
        let pending = Pin::new(io).poll_read(&mut cx, &mut buf);
        assert!(pending.is_pending());
        wake_counters.push(counter);
    }

    let mut observed = vec![0usize; waiters];
    let start = Instant::now();
    let mut wakes_at_40ms = 0usize;
    let mut wakes_at_160ms = 0usize;

    while start.elapsed() < Duration::from_millis(200) {
        for (idx, counter) in wake_counters.iter().enumerate() {
            let wakes = counter.wakes.load(Ordering::Relaxed);
            if wakes > observed[idx] {
                observed[idx] = wakes;
                let waker = Waker::from(Arc::clone(counter));
                let mut cx = Context::from_waker(&waker);
                let mut storage = [0u8; 1];
                let mut buf = ReadBuf::new(&mut storage);
                let pending = Pin::new(&mut ios[idx]).poll_read(&mut cx, &mut buf);
                assert!(pending.is_pending());
            }
        }

        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(40) && wakes_at_40ms == 0 {
            wakes_at_40ms = wake_counters
                .iter()
                .map(|counter| counter.wakes.load(Ordering::Relaxed))
                .sum();
        }
        if elapsed >= Duration::from_millis(160) && wakes_at_160ms == 0 {
            wakes_at_160ms = wake_counters
                .iter()
                .map(|counter| counter.wakes.load(Ordering::Relaxed))
                .sum();
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let total_wakes: usize = wake_counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    let wakes_at_200ms = total_wakes;
    let early_window_wakes = wakes_at_40ms;
    let late_window_wakes = wakes_at_200ms.saturating_sub(wakes_at_160ms);

    assert!(
        total_wakes <= waiters * 28,
        "read backoff benchmark exceeded wake budget; waiters={waiters}, wakes={total_wakes}"
    );

    assert!(
        early_window_wakes > 0,
        "read benchmark failed to observe early contention wakes"
    );

    assert!(
        late_window_wakes * 4 <= early_window_wakes * 3,
        "read wake-rate decay invariant violated; early_0_40ms={early_window_wakes}, late_160_200ms={late_window_wakes}, total={total_wakes}"
    );

    drop(held_guard);
}
