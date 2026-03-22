use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWriteExt, duplex};

fn make_crypto_reader<T>(reader: T) -> CryptoReader<T>
where
    T: AsyncRead + Unpin + Send + 'static,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

fn make_forensics(conn_id: u64, started_at: Instant) -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 0xB100_0000 + conn_id,
        conn_id,
        user: format!("tiny-frame-debt-user-{conn_id}"),
        peer: "127.0.0.1:50000".parse().expect("peer parse must succeed"),
        peer_hash: hash_ip("127.0.0.1".parse().expect("ip parse must succeed")),
        started_at,
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_enabled_idle_policy() -> RelayClientIdlePolicy {
    RelayClientIdlePolicy {
        enabled: true,
        soft_idle: Duration::from_secs(30),
        hard_idle: Duration::from_secs(60),
        grace_after_downstream_activity: Duration::from_secs(0),
        legacy_frame_read_timeout: Duration::from_secs(30),
    }
}

fn simulate_tiny_debt_pattern(pattern: &[bool], max_steps: usize) -> (Option<usize>, u32, usize) {
    let mut debt = 0u32;
    let mut reals = 0usize;
    for (idx, is_tiny) in pattern.iter().copied().take(max_steps).enumerate() {
        if is_tiny {
            debt = debt.saturating_add(TINY_FRAME_DEBT_PER_TINY);
            if debt >= TINY_FRAME_DEBT_LIMIT {
                return (Some(idx + 1), debt, reals);
            }
        } else {
            reals = reals.saturating_add(1);
            debt = debt.saturating_sub(1);
        }
    }
    (None, debt, reals)
}

#[test]
fn tiny_frame_debt_constants_match_security_budget_expectations() {
    assert_eq!(TINY_FRAME_DEBT_PER_TINY, 8);
    assert_eq!(TINY_FRAME_DEBT_LIMIT, 512);
}

#[test]
fn relay_client_idle_state_initial_debt_is_zero() {
    let state = RelayClientIdleState::new(Instant::now());
    assert_eq!(state.tiny_frame_debt, 0);
}

#[test]
fn on_client_frame_does_not_reset_tiny_frame_debt() {
    let now = Instant::now();
    let mut state = RelayClientIdleState::new(now);
    state.tiny_frame_debt = 77;
    state.on_client_frame(now);
    assert_eq!(state.tiny_frame_debt, 77);
}

#[test]
fn tiny_frame_debt_increment_is_saturating() {
    let mut debt = u32::MAX - 1;
    debt = debt.saturating_add(TINY_FRAME_DEBT_PER_TINY);
    assert_eq!(debt, u32::MAX);
}

#[test]
fn tiny_frame_debt_decrement_is_saturating() {
    let mut debt = 0u32;
    debt = debt.saturating_sub(1);
    assert_eq!(debt, 0);
}

#[test]
fn consecutive_tiny_frames_close_exactly_at_threshold() {
    let max_tiny_without_close = (TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) as usize;
    let pattern = vec![true; max_tiny_without_close];
    let (closed_at, _, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, Some(max_tiny_without_close));
}

#[test]
fn one_less_than_threshold_tiny_frames_do_not_close() {
    let tiny_count = (TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) as usize - 1;
    let pattern = vec![true; tiny_count];
    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert!(debt < TINY_FRAME_DEBT_LIMIT);
}

#[test]
fn alternating_one_to_one_closes_with_bounded_real_frame_count() {
    let mut pattern = Vec::with_capacity(512);
    for _ in 0..256 {
        pattern.push(true);
        pattern.push(false);
    }
    let (closed_at, _, reals) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert!(closed_at.is_some());
    assert!(reals <= 80, "expected bounded real frames before close, got {reals}");
}

#[test]
fn alternating_one_to_eight_is_stable_for_long_runs() {
    let mut pattern = Vec::with_capacity(9 * 5000);
    for _ in 0..5000 {
        pattern.push(true);
        for _ in 0..8 {
            pattern.push(false);
        }
    }
    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert!(debt <= TINY_FRAME_DEBT_PER_TINY);
}

#[test]
fn alternating_one_to_seven_eventually_closes() {
    let mut pattern = Vec::with_capacity(8 * 2000);
    for _ in 0..2000 {
        pattern.push(true);
        for _ in 0..7 {
            pattern.push(false);
        }
    }
    let (closed_at, _, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert!(closed_at.is_some(), "1:7 tiny-to-real must eventually close");
}

#[test]
fn two_tiny_one_real_closes_faster_than_one_to_one() {
    let mut one_to_one = Vec::with_capacity(512);
    for _ in 0..256 {
        one_to_one.push(true);
        one_to_one.push(false);
    }

    let mut two_to_one = Vec::with_capacity(768);
    for _ in 0..256 {
        two_to_one.push(true);
        two_to_one.push(true);
        two_to_one.push(false);
    }

    let (a_close, _, _) = simulate_tiny_debt_pattern(&one_to_one, one_to_one.len());
    let (b_close, _, _) = simulate_tiny_debt_pattern(&two_to_one, two_to_one.len());
    assert!(a_close.is_some() && b_close.is_some());
    assert!(b_close.unwrap_or(usize::MAX) < a_close.unwrap_or(0));
}

#[test]
fn burst_then_drain_can_recover_without_close() {
    let burst_tiny = ((TINY_FRAME_DEBT_LIMIT / TINY_FRAME_DEBT_PER_TINY) / 2) as usize;
    let mut pattern = Vec::with_capacity(burst_tiny + 600);
    for _ in 0..burst_tiny {
        pattern.push(true);
    }
    pattern.extend(std::iter::repeat_n(false, 600));

    let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
    assert_eq!(closed_at, None);
    assert_eq!(debt, 0);
}

#[test]
fn light_fuzz_tiny_frame_debt_model_stays_within_bounds() {
    let mut seed = 0xA5A5_91C3_2026_0322u64;
    for _case in 0..128 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let len = 512 + ((seed as usize) & 0x3ff);
        let mut pattern = Vec::with_capacity(len);
        let mut local_seed = seed;
        for _ in 0..len {
            local_seed ^= local_seed << 7;
            local_seed ^= local_seed >> 9;
            local_seed ^= local_seed << 8;
            pattern.push((local_seed & 1) == 0);
        }

        let (closed_at, debt, _) = simulate_tiny_debt_pattern(&pattern, pattern.len());
        if closed_at.is_none() {
            assert!(debt < TINY_FRAME_DEBT_LIMIT);
        }
        assert!(debt <= u32::MAX);
    }
}

#[test]
fn stress_many_independent_simulations_keep_isolated_debt_state() {
    for idx in 0..2048usize {
        let mut pattern = Vec::with_capacity(64);
        for j in 0..64usize {
            pattern.push(((idx ^ j) & 3) == 0);
        }
        let (_closed_at, debt, _reals) = simulate_tiny_debt_pattern(&pattern, pattern.len());
        assert!(debt <= TINY_FRAME_DEBT_LIMIT.saturating_add(TINY_FRAME_DEBT_PER_TINY));
    }
}

#[tokio::test]
async fn idle_policy_enabled_intermediate_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(11, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 4 * 256];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::Proxy(_))));
}

#[tokio::test]
async fn idle_policy_enabled_secure_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(12, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 4 * 256];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer.write_all(&flood_encrypted).await.unwrap();
    drop(writer);

    let result = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::Proxy(_))));
}

#[tokio::test]
async fn intermediate_alternating_zero_and_real_eventually_closes() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(13, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(3000);
    for idx in 0..160u8 {
        plaintext.extend_from_slice(&0u32.to_le_bytes());
        plaintext.extend_from_slice(&4u32.to_le_bytes());
        plaintext.extend_from_slice(&[idx, idx ^ 0x11, idx ^ 0x22, idx ^ 0x33]);
    }
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();
    drop(writer);

    let mut closed = false;
    for _ in 0..220 {
        let result = read_client_payload_with_idle_policy(
            &mut crypto_reader,
            ProtoTag::Intermediate,
            1024,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        )
        .await;

        match result {
            Ok(Some(_)) => {}
            Err(ProxyError::Proxy(_)) => {
                closed = true;
                break;
            }
            Ok(None) => break,
            Err(other) => panic!("unexpected error while probing alternating close: {other}"),
        }
    }

    assert!(closed, "intermediate alternating attack must fail closed");
}

#[tokio::test]
async fn small_tiny_burst_followed_by_real_frame_does_not_spuriously_close() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(14, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(64);
    for _ in 0..8 {
        plaintext.push(0x00);
    }
    plaintext.push(0x01);
    plaintext.extend_from_slice(&[1, 2, 3, 4]);

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let first = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Abridged,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    match first {
        Ok(Some((payload, _))) => assert_eq!(payload.as_ref(), &[1, 2, 3, 4]),
        Err(e) => panic!("unexpected close after small tiny burst: {e}"),
        Ok(None) => panic!("unexpected EOF before real frame"),
    }
}

#[tokio::test]
async fn idle_policy_enabled_zero_length_flood_is_fail_closed() {
    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(1, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let flood_plaintext = vec![0u8; 1024];
    let flood_encrypted = encrypt_for_reader(&flood_plaintext);
    writer
        .write_all(&flood_encrypted)
        .await
        .expect("zero-length flood bytes must be writable");
    drop(writer);

    let result = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Abridged,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(_))),
        "idle policy enabled must fail closed for pure zero-length flood"
    );
}

#[tokio::test]
async fn idle_policy_enabled_alternating_tiny_real_eventually_closes() {
    let (reader, mut writer) = duplex(8192);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(2, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let mut plaintext = Vec::with_capacity(256 * 6);
    for idx in 0..=255u8 {
        plaintext.push(0x00);
        plaintext.push(0x01);
        plaintext.extend_from_slice(&[idx, idx ^ 0x55, idx ^ 0xAA, 0x11]);
    }

    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("alternating flood bytes must be writable");
    drop(writer);

    let mut saw_proxy_close = false;
    for _ in 0..300 {
        let result = read_client_payload_with_idle_policy(
            &mut crypto_reader,
            ProtoTag::Abridged,
            1024,
            &buffer_pool,
            &forensics,
            &mut frame_counter,
            &stats,
            &idle_policy,
            &mut idle_state,
            &last_downstream_activity_ms,
            session_started_at,
        )
        .await;

        match result {
            Ok(Some((_payload, _quickack))) => {}
            Err(ProxyError::Proxy(_)) => {
                saw_proxy_close = true;
                break;
            }
            Err(ProxyError::Io(e)) => panic!("unexpected IO error before close: {e}"),
            Ok(None) => panic!("unexpected EOF before debt-based closure"),
            Err(other) => panic!("unexpected error before close: {other}"),
        }
    }

    assert!(
        saw_proxy_close,
        "alternating tiny/real sequence must eventually fail closed"
    );
}

#[tokio::test]
async fn enabled_idle_policy_valid_nonzero_frame_still_passes() {
    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let session_started_at = Instant::now();
    let forensics = make_forensics(3, session_started_at);
    let mut frame_counter = 0u64;
    let mut idle_state = RelayClientIdleState::new(session_started_at);
    let idle_policy = make_enabled_idle_policy();
    let last_downstream_activity_ms = AtomicU64::new(0);

    let payload = [7u8, 8, 9, 10];
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(0x01);
    plaintext.extend_from_slice(&payload);

    let encrypted = encrypt_for_reader(&plaintext);
    writer
        .write_all(&encrypted)
        .await
        .expect("nonzero frame must be writable");

    let result = read_client_payload_with_idle_policy(
        &mut crypto_reader,
        ProtoTag::Abridged,
        1024,
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        session_started_at,
    )
    .await
    .expect("valid frame should decode")
    .expect("valid frame should return payload");

    assert_eq!(result.0.as_ref(), &payload);
    assert!(!result.1);
    assert_eq!(frame_counter, 1);
}
