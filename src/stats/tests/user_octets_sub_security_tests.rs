use super::*;
use std::sync::Arc;
use std::thread;

#[test]
fn sub_user_octets_to_underflow_saturates_at_zero() {
    let stats = Stats::new();
    let user = "sub-underflow-user";

    stats.add_user_octets_to(user, 3);
    stats.sub_user_octets_to(user, 100);

    assert_eq!(stats.get_user_total_octets(user), 0);
}

#[test]
fn sub_user_octets_to_does_not_affect_octets_from_client() {
    let stats = Stats::new();
    let user = "sub-isolation-user";

    stats.add_user_octets_from(user, 17);
    stats.add_user_octets_to(user, 5);
    stats.sub_user_octets_to(user, 3);

    assert_eq!(stats.get_user_total_octets(user), 19);
}

#[test]
fn light_fuzz_add_sub_model_matches_saturating_reference() {
    let stats = Stats::new();
    let user = "sub-fuzz-user";
    let mut seed = 0x91D2_4CB8_EE77_1101u64;
    let mut model_to = 0u64;

    for _ in 0..8192 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let amt = ((seed >> 8) & 0x3f) + 1;
        if (seed & 1) == 0 {
            stats.add_user_octets_to(user, amt);
            model_to = model_to.saturating_add(amt);
        } else {
            stats.sub_user_octets_to(user, amt);
            model_to = model_to.saturating_sub(amt);
        }
    }

    assert_eq!(stats.get_user_total_octets(user), model_to);
}

#[test]
fn stress_parallel_add_sub_never_underflows_or_panics() {
    let stats = Arc::new(Stats::new());
    let user = "sub-stress-user";
    // Pre-fund with a large offset so subtractions never saturate at zero.
    // This guarantees commutative updates, making the final state deterministic.
    let base_offset = 10_000_000u64;
    stats.add_user_octets_to(user, base_offset);

    let mut workers = Vec::new();

    for tid in 0..16u64 {
        let stats_for_thread = Arc::clone(&stats);
        workers.push(thread::spawn(move || {
            let mut seed = 0xD00D_1000_0000_0000u64 ^ tid;
            let mut net_delta = 0i64;
            for _ in 0..4096 {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                let amt = ((seed >> 8) & 0x1f) + 1;

                if (seed & 1) == 0 {
                    stats_for_thread.add_user_octets_to(user, amt);
                    net_delta += amt as i64;
                } else {
                    stats_for_thread.sub_user_octets_to(user, amt);
                    net_delta -= amt as i64;
                }
            }

            net_delta
        }));
    }

    let mut expected_net_delta = 0i64;
    for worker in workers {
        expected_net_delta += worker
            .join()
            .expect("sub-user stress worker must not panic");
    }

    let expected_total = (base_offset as i64 + expected_net_delta) as u64;
    let total = stats.get_user_total_octets(user);
    assert_eq!(
        total, expected_total,
        "concurrent add/sub lost updates or suffered ABA races"
    );
}

#[test]
fn sub_user_octets_to_missing_user_is_noop() {
    let stats = Stats::new();
    stats.sub_user_octets_to("missing-user", 1024);
    assert_eq!(stats.get_user_total_octets("missing-user"), 0);
}

#[test]
fn stress_parallel_per_user_models_remain_exact() {
    let stats = Arc::new(Stats::new());
    let mut workers = Vec::new();

    for tid in 0..16u64 {
        let stats_for_thread = Arc::clone(&stats);
        workers.push(thread::spawn(move || {
            let user = format!("sub-per-user-{tid}");
            let mut seed = 0xFACE_0000_0000_0000u64 ^ tid;
            let mut model = 0u64;

            for _ in 0..4096 {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                let amt = ((seed >> 8) & 0x3f) + 1;

                if (seed & 1) == 0 {
                    stats_for_thread.add_user_octets_to(&user, amt);
                    model = model.saturating_add(amt);
                } else {
                    stats_for_thread.sub_user_octets_to(&user, amt);
                    model = model.saturating_sub(amt);
                }
            }

            (user, model)
        }));
    }

    for worker in workers {
        let (user, model) = worker
            .join()
            .expect("per-user subtract stress worker must not panic");
        assert_eq!(
            stats.get_user_total_octets(&user),
            model,
            "per-user parallel model diverged"
        );
    }
}