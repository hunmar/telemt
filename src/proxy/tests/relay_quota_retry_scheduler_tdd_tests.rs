use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::time::{Duration, timeout};

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

#[tokio::test]
async fn positive_uncontended_quota_limited_writer_completes() {
    let _guard = quota_test_guard();

    let stats = Arc::new(Stats::new());
    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        "tdd-uncontended".to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let result = io.write_all(&[0x41, 0x42, 0x43]).await;
    assert!(result.is_ok(), "uncontended writer must complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_contended_writers_without_repoll_must_not_wake_storm() {
    let _guard = quota_test_guard();

    let user = format!("tdd-writer-storm-{}", std::process::id());
    let held = quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold quota lock before polling writers");

    let stats = Arc::new(Stats::new());
    let writers = 24usize;
    let mut ios = Vec::with_capacity(writers);
    let mut wake_counters = Vec::with_capacity(writers);

    for _ in 0..writers {
        ios.push(StatsIo::new(
            tokio::io::sink(),
            Arc::new(SharedCounters::new()),
            Arc::clone(&stats),
            user.clone(),
            Some(1024),
            Arc::new(AtomicBool::new(false)),
            tokio::time::Instant::now(),
        ));
    }

    for io in &mut ios {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(io).poll_write(&mut cx, &[0xAA]);
        assert!(poll.is_pending(), "writer must be pending under held lock");
        wake_counters.push(counter);
    }

    tokio::time::sleep(Duration::from_millis(25)).await;

    let total_wakes: usize = wake_counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    assert!(
        total_wakes <= writers * 4,
        "retry scheduler must remain bounded without repoll; observed wakes={total_wakes}, writers={writers}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_contended_readers_without_repoll_must_not_wake_storm() {
    let _guard = quota_test_guard();

    let user = format!("tdd-reader-storm-{}", std::process::id());
    let held = quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold quota lock before polling readers");

    let stats = Arc::new(Stats::new());
    let readers = 24usize;
    let mut ios = Vec::with_capacity(readers);
    let mut wake_counters = Vec::with_capacity(readers);

    for _ in 0..readers {
        ios.push(StatsIo::new(
            tokio::io::empty(),
            Arc::new(SharedCounters::new()),
            Arc::clone(&stats),
            user.clone(),
            Some(1024),
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
        let poll = Pin::new(io).poll_read(&mut cx, &mut buf);
        assert!(poll.is_pending(), "reader must be pending under held lock");
        wake_counters.push(counter);
    }

    tokio::time::sleep(Duration::from_millis(25)).await;

    let total_wakes: usize = wake_counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    assert!(
        total_wakes <= readers * 4,
        "retry scheduler must remain bounded without repoll; observed wakes={total_wakes}, readers={readers}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_contended_waiters_resume_after_lock_release() {
    let _guard = quota_test_guard();

    let user = format!("tdd-resume-{}", std::process::id());
    let held = quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold quota lock before launching waiters");

    let stats = Arc::new(Stats::new());
    let mut waiters = Vec::new();
    for _ in 0..12 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        waiters.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                stats,
                user,
                Some(2048),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x5A]).await
        }));
    }

    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(held_guard);

    timeout(Duration::from_secs(1), async {
        for waiter in waiters {
            let result = waiter.await.expect("waiter task must not panic");
            assert!(result.is_ok(), "waiter must complete after release");
        }
    })
    .await
    .expect("all waiters must complete in bounded time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_contention_rounds_keep_retry_wakes_bounded() {
    let _guard = quota_test_guard();

    let mut seed = 0x9E37_79B9_AA55_1234u64;
    for round in 0..20u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let writers = 8 + (seed as usize % 12);
        let sleep_ms = 10 + (seed as u64 % 15);
        let user = format!("tdd-fuzz-{}-{round}", std::process::id());

        let held = quota_user_lock(&user);
        let _held_guard = held
            .try_lock()
            .expect("test must hold quota lock in fuzz round");

        let stats = Arc::new(Stats::new());
        let mut ios = Vec::with_capacity(writers);
        let mut wake_counters = Vec::with_capacity(writers);

        for _ in 0..writers {
            ios.push(StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::clone(&stats),
                user.clone(),
                Some(2048),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            ));
        }

        for io in &mut ios {
            let counter = Arc::new(WakeCounter::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut cx = Context::from_waker(&waker);
            let poll = Pin::new(io).poll_write(&mut cx, &[0x7A]);
            assert!(matches!(poll, Poll::Pending));
            wake_counters.push(counter);
        }

        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

        let total_wakes: usize = wake_counters
            .iter()
            .map(|counter| counter.wakes.load(Ordering::Relaxed))
            .sum();

        assert!(
            total_wakes <= writers * 4,
            "fuzz round must keep wakes bounded; round={round}, writers={writers}, wakes={total_wakes}, sleep_ms={sleep_ms}"
        );
    }
}
