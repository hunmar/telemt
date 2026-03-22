use super::*;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

fn cross_mode_lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn same_user_returns_same_lock_identity() {
    let _guard = cross_mode_lock_test_guard();
    let locks = CROSS_MODE_QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    locks.clear();

    let a = cross_mode_quota_user_lock("cross-mode-same-user");
    let b = cross_mode_quota_user_lock("cross-mode-same-user");

    assert!(
        Arc::ptr_eq(&a, &b),
        "same user must reuse a stable lock identity"
    );
}

#[test]
fn saturation_overflow_path_returns_stable_striped_lock_without_cache_growth() {
    let _guard = cross_mode_lock_test_guard();
    let locks = CROSS_MODE_QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    locks.clear();

    let prefix = format!("cross-mode-saturated-{}", std::process::id());
    let mut retained = Vec::with_capacity(CROSS_MODE_QUOTA_USER_LOCKS_MAX);
    for idx in 0..CROSS_MODE_QUOTA_USER_LOCKS_MAX {
        retained.push(cross_mode_quota_user_lock(&format!("{prefix}-{idx}")));
    }

    assert_eq!(
        locks.len(),
        CROSS_MODE_QUOTA_USER_LOCKS_MAX,
        "lock cache must be saturated for overflow check"
    );

    let overflow_user = format!("cross-mode-overflow-{}", std::process::id());
    let overflow_a = cross_mode_quota_user_lock(&overflow_user);
    let overflow_b = cross_mode_quota_user_lock(&overflow_user);

    assert_eq!(
        locks.len(),
        CROSS_MODE_QUOTA_USER_LOCKS_MAX,
        "overflow path must not grow bounded lock cache"
    );
    assert!(
        locks.get(&overflow_user).is_none(),
        "overflow user must stay on striped fallback while cache is saturated"
    );
    assert!(
        Arc::ptr_eq(&overflow_a, &overflow_b),
        "overflow user must receive a stable striped lock across repeated lookups"
    );

    drop(retained);
}

#[test]
fn reclaim_drops_stale_entries_but_preserves_active_user_lock_identity() {
    let _guard = cross_mode_lock_test_guard();
    let locks = CROSS_MODE_QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    locks.clear();

    let prefix = format!("cross-mode-reclaim-{}", std::process::id());
    let protected_user = format!("{prefix}-protected");

    let protected_lock = cross_mode_quota_user_lock(&protected_user);
    let mut retained = Vec::with_capacity(CROSS_MODE_QUOTA_USER_LOCKS_MAX.saturating_sub(1));
    for idx in 0..(CROSS_MODE_QUOTA_USER_LOCKS_MAX.saturating_sub(1)) {
        retained.push(cross_mode_quota_user_lock(&format!("{prefix}-{idx}")));
    }

    assert_eq!(
        locks.len(),
        CROSS_MODE_QUOTA_USER_LOCKS_MAX,
        "fixture must saturate lock cache before reclaim path is exercised"
    );

    drop(retained);

    let newcomer_user = format!("{prefix}-newcomer");
    let _newcomer = cross_mode_quota_user_lock(&newcomer_user);

    assert!(
        locks.get(&protected_user).is_some(),
        "active protected user must remain cache-resident after reclaim"
    );
    let locked = locks
        .get(&protected_user)
        .expect("protected user must remain in map after reclaim");
    assert!(
        Arc::ptr_eq(locked.value(), &protected_lock),
        "reclaim must not swap active user lock identity"
    );
    assert!(
        locks.get(&newcomer_user).is_some(),
        "newcomer should become cacheable after stale entries are reclaimed"
    );
}
