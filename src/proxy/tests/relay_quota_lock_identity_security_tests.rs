use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    // Context stores a reference; leak one Waker for deterministic test scope.
    let leaked_waker: &'static Waker = Box::leak(Box::new(waker));
    (wake_counter, Context::from_waker(leaked_waker))
}

#[tokio::test]
async fn adversarial_map_churn_cannot_bypass_held_writer_lock() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let user = "quota-identity-writer-user";
    let held_lock = quota_user_lock(user);
    let _held_guard = held_lock
        .try_lock()
        .expect("test must hold initial user lock before StatsIo poll");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    map.clear();
    let churned_lock = quota_user_lock(user);
    assert!(
        !Arc::ptr_eq(&held_lock, &churned_lock),
        "precondition: map churn should produce a distinct lock identity"
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x11, 0x22, 0x33, 0x44]);

    assert!(
        matches!(poll, Poll::Pending),
        "writer must remain pending on the originally-held lock identity"
    );
}

#[tokio::test]
async fn adversarial_map_churn_cannot_bypass_held_reader_lock() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let user = "quota-identity-reader-user";
    let held_lock = quota_user_lock(user);
    let _held_guard = held_lock
        .try_lock()
        .expect("test must hold initial user lock before StatsIo poll");

    let mut io = StatsIo::new(
        tokio::io::empty(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    map.clear();
    let churned_lock = quota_user_lock(user);
    assert!(
        !Arc::ptr_eq(&held_lock, &churned_lock),
        "precondition: map churn should produce a distinct lock identity"
    );

    let (_wake_counter, mut cx) = build_context();
    let mut storage = [0u8; 8];
    let mut read_buf = ReadBuf::new(&mut storage);
    let poll = Pin::new(&mut io).poll_read(&mut cx, &mut read_buf);

    assert!(
        matches!(poll, Poll::Pending),
        "reader must remain pending on the originally-held lock identity"
    );
}

#[tokio::test]
async fn business_no_lock_contention_keeps_writer_progress() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let user = "quota-identity-progress-user";
    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user.to_string(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0xAA, 0xBB]);

    assert!(
        matches!(poll, Poll::Ready(Ok(2))),
        "writer should progress immediately without contention"
    );
}
