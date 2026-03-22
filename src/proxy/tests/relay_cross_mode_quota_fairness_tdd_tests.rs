use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
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
async fn positive_cross_mode_uncontended_writer_progresses() {
    let _guard = quota_test_guard();

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        "cross-mode-tdd-uncontended".to_string(),
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let result = io.write_all(&[0x11, 0x22]).await;
    assert!(result.is_ok(), "uncontended writer must progress");
}

#[tokio::test]
async fn adversarial_held_cross_mode_lock_blocks_writer_even_if_local_lock_free() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-held-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before polling writer");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0xAA]);
    assert!(poll.is_pending(), "writer must not bypass held cross-mode lock");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_parallel_waiters_resume_after_cross_mode_release() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-resume-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before launching waiters");

    let stats = Arc::new(Stats::new());
    let mut waiters = Vec::new();
    for _ in 0..16 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        waiters.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                stats,
                user,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x7F]).await
        }));
    }

    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(held_guard);

    timeout(Duration::from_secs(1), async {
        for waiter in waiters {
            let result = waiter.await.expect("waiter task must not panic");
            assert!(result.is_ok(), "waiter must complete after cross-mode release");
        }
    })
    .await
    .expect("all waiters must complete in bounded time");
}

#[tokio::test]
async fn adversarial_cross_mode_contention_wake_budget_stays_bounded() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-wakes-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before polling");

    let stats = Arc::new(Stats::new());
    let mut ios = Vec::new();
    let mut counters = Vec::new();
    for _ in 0..20 {
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
        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(io).poll_write(&mut cx, &[0x33]);
        assert!(poll.is_pending());
        counters.push(wake_counter);
    }

    tokio::time::sleep(Duration::from_millis(25)).await;
    let total_wakes: usize = counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    assert!(
        total_wakes <= 20 * 4,
        "cross-mode contention should not create wake storms; wakes={total_wakes}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_cross_mode_release_timing_preserves_read_write_liveness() {
    let _guard = quota_test_guard();

    let mut seed = 0xC0DE_BAAD_2026_0322u64;
    for round in 0..16u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let sleep_ms = 2 + (seed as u64 % 8);
        let user = format!("cross-mode-tdd-fuzz-{}-{round}", std::process::id());
        let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
        let held_guard = held
            .try_lock()
            .expect("test must hold cross-mode lock in fuzz round");

        let stats = Arc::new(Stats::new());
        let user_reader = user.clone();
        let reader_task = tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::empty(),
                Arc::new(SharedCounters::new()),
                Arc::clone(&stats),
                user_reader,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            let mut one = [0u8; 1];
            io.read(&mut one).await
        });

        let user_writer = user.clone();
        let writer_task = tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user_writer,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x44]).await
        });

        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        drop(held_guard);

        let read_done = timeout(Duration::from_millis(350), reader_task)
            .await
            .expect("reader task must complete after release")
            .expect("reader task must not panic");
        assert!(read_done.is_ok());

        let write_done = timeout(Duration::from_millis(350), writer_task)
            .await
            .expect("writer task must complete after release")
            .expect("writer task must not panic");
        assert!(write_done.is_ok());
    }
}
