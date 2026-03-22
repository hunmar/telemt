use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::task::JoinSet;

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

#[tokio::test]
async fn positive_exact_quota_boundary_allows_last_frame_and_blocks_next() {
    let stats = Stats::new();
    let user = "quota-boundary-user";
    let bytes_me2c = AtomicU64::new(0);

    stats.add_user_octets_from(user, 5);

    let mut writer_one = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_one = Vec::new();
    let first = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer_one,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_one,
        &stats,
        user,
        Some(8),
        &bytes_me2c,
        7101,
        false,
        false,
    )
    .await;

    assert!(first.is_ok(), "frame that reaches boundary must be allowed");
    assert_eq!(stats.get_user_total_octets(user), 8);

    let mut writer_two = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_two = Vec::new();
    let second = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[9]),
        },
        &mut writer_two,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_two,
        &stats,
        user,
        Some(8),
        &bytes_me2c,
        7102,
        false,
        false,
    )
    .await;

    assert!(
        matches!(second, Err(ProxyError::DataQuotaExceeded { .. })),
        "frame after boundary must be rejected"
    );
    assert_eq!(stats.get_user_total_octets(user), 8);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_parallel_reservation_stress_never_overshoots_quota_or_counters() {
    let stats = Arc::new(Stats::new());
    let user = "reservation-stress-user";
    let quota_limit = 64u64;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();

    for idx in 0..256u64 {
        let user_owned = user.to_string();
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_me2c);

        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xAB]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                &user_owned,
                Some(quota_limit),
                bytes_ref.as_ref(),
                7200 + idx,
                false,
                false,
            )
            .await
        });
    }

    let mut ok = 0usize;
    let mut denied = 0usize;
    while let Some(joined) = tasks.join_next().await {
        match joined.expect("reservation stress task must not panic") {
            Ok(_) => ok += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => denied += 1,
            Err(other) => panic!("unexpected error in stress case: {other:?}"),
        }
    }

    let total = stats.get_user_total_octets(user);
    assert_eq!(
        total, quota_limit,
        "quota must be exactly exhausted without overshoot"
    );
    assert_eq!(
        bytes_me2c.load(Ordering::Relaxed),
        total,
        "ME->C forensic bytes must track committed quota usage"
    );
    assert_eq!(ok, quota_limit as usize, "exactly quota_limit tasks must succeed");
    assert_eq!(
        denied,
        256usize - (quota_limit as usize),
        "remaining tasks must be exactly denied without silently swallowing state"
    );
}

#[tokio::test]
async fn light_fuzz_random_frame_sizes_preserve_quota_and_counter_consistency() {
    let stats = Stats::new();
    let user = "reservation-fuzz-user";
    let quota_limit = 128u64;
    let bytes_me2c = AtomicU64::new(0);
    let mut seed = 0xC0FE_EE11_8899_2211u64;

    for conn in 0..512u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let len = ((seed & 0x0f) + 1) as usize;
        let payload = vec![0x5A; len];

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let result = process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(payload),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            user,
            Some(quota_limit),
            &bytes_me2c,
            7300 + conn,
            false,
            false,
        )
        .await;

        if let Err(err) = result {
            assert!(
                matches!(err, ProxyError::DataQuotaExceeded { .. }),
                "fuzz run produced unexpected error variant: {err:?}"
            );
        }
    }

    let total = stats.get_user_total_octets(user);
    assert!(total <= quota_limit);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), total);
}