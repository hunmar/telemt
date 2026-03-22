use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use std::task::{Context, Poll};

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

fn build_context() -> (Arc<WakeCounter>, Context<'static>) {
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let leaked_waker: &'static Waker = Box::leak(Box::new(waker));
    (wake_counter, Context::from_waker(leaked_waker))
}

#[tokio::test]
async fn adversarial_middle_held_cross_mode_lock_blocks_relay_writer() {
    let _guard = quota_user_lock_test_scope();

    let user = "cross-mode-lock-shared-user";
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold shared cross-mode lock before relay poll");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(crate::stats::Stats::new()),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x41, 0x42, 0x43]);

    assert!(
        matches!(poll, Poll::Pending),
        "relay writer must not bypass cross-mode lock held by middle-relay path"
    );
}

#[tokio::test]
async fn business_cross_mode_lock_uncontended_allows_relay_writer_progress() {
    let _guard = quota_user_lock_test_scope();

    let user = "cross-mode-lock-progress-user";
    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(crate::stats::Stats::new()),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x51, 0x52]);

    assert!(
        matches!(poll, Poll::Ready(Ok(2))),
        "relay writer should progress when shared cross-mode lock is uncontended"
    );
}
