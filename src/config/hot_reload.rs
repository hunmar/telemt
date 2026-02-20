//! Hot-reload: watches the config file and reloads it on SIGHUP (Unix)
//! or on a periodic timer (all platforms).
//!
//! # What can be reloaded without restart
//!
//! | Section   | Field                         | Effect                          |
//! |-----------|-------------------------------|---------------------------------|
//! | `general` | `log_level`                   | Filter updated via `log_level_tx` |
//! | `general` | `ad_tag`                      | Passed on next connection       |
//! | `general` | `middle_proxy_pool_size`      | Passed on next connection       |
//! | `general` | `me_keepalive_*`              | Passed on next connection       |
//! | `access`  | All user/quota fields         | Effective immediately           |
//!
//! Fields that require re-binding sockets (`server.port`, `censorship.*`,
//! `network.*`, `use_middle_proxy`) are **not** applied; a warning is emitted.
//!
//! # Usage
//!
//! ```rust,ignore
//! let (config_rx, log_level_rx) = spawn_config_watcher(
//!     PathBuf::from("config.toml"),
//!     initial_config.clone(),
//!     Duration::from_secs(60),
//! );
//!
//! // In each accept-loop, get a fresh snapshot per connection:
//! let config = config_rx.borrow_and_update().clone();
//!
//! // In a separate task, apply log_level changes to the tracing filter:
//! tokio::spawn(async move {
//!     loop {
//!         log_level_rx.changed().await.ok();
//!         let level = log_level_rx.borrow().clone();
//!         filter_handle.reload(EnvFilter::new(level.to_filter_str())).ok();
//!     }
//! });
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::LogLevel;
use super::load::ProxyConfig;

/// Fields that are safe to swap without restarting listeners.
#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub log_level:               LogLevel,
    pub ad_tag:                  Option<String>,
    pub middle_proxy_pool_size:  usize,
    pub me_keepalive_enabled:    bool,
    pub me_keepalive_interval_secs: u64,
    pub me_keepalive_jitter_secs:   u64,
    pub me_keepalive_payload_random: bool,
    pub access:                  crate::config::AccessConfig,
}

impl HotFields {
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        Self {
            log_level:               cfg.general.log_level.clone(),
            ad_tag:                  cfg.general.ad_tag.clone(),
            middle_proxy_pool_size:  cfg.general.middle_proxy_pool_size,
            me_keepalive_enabled:    cfg.general.me_keepalive_enabled,
            me_keepalive_interval_secs: cfg.general.me_keepalive_interval_secs,
            me_keepalive_jitter_secs:   cfg.general.me_keepalive_jitter_secs,
            me_keepalive_payload_random: cfg.general.me_keepalive_payload_random,
            access:                  cfg.access.clone(),
        }
    }
}

/// Warn if any non-hot fields changed (i.e. require restart).
fn warn_non_hot_changes(old: &ProxyConfig, new: &ProxyConfig) {
    if old.server.port != new.server.port {
        warn!(
            "config reload: server.port changed ({} → {}); restart required",
            old.server.port, new.server.port
        );
    }
    if old.censorship.tls_domain != new.censorship.tls_domain {
        warn!(
            "config reload: censorship.tls_domain changed ('{}' → '{}'); restart required",
            old.censorship.tls_domain, new.censorship.tls_domain
        );
    }
    if old.network.ipv4 != new.network.ipv4 || old.network.ipv6 != new.network.ipv6 {
        warn!("config reload: network.ipv4/ipv6 changed; restart required");
    }
    if old.general.use_middle_proxy != new.general.use_middle_proxy {
        warn!("config reload: use_middle_proxy changed; restart required");
    }
}

/// Spawn the hot-reload watcher task.
///
/// Returns:
/// - `watch::Receiver<Arc<ProxyConfig>>` — every accept-loop should call
///   `.borrow_and_update().clone()` per accepted connection.
/// - `watch::Receiver<LogLevel>` — caller should watch this and apply changes
///   to the `tracing` reload handle (avoids lifetime/generic issues).
pub fn spawn_config_watcher(
    config_path: PathBuf,
    initial: Arc<ProxyConfig>,
    reload_interval: Duration,
) -> (watch::Receiver<Arc<ProxyConfig>>, watch::Receiver<LogLevel>) {
    let initial_level = initial.general.log_level.clone();
    let (config_tx, config_rx) = watch::channel(initial);
    let (log_tx, log_rx)       = watch::channel(initial_level);

    tokio::spawn(async move {
        // On Unix, also listen for SIGHUP.
        #[cfg(unix)]
        let mut sighup = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler")
        };

        let mut interval = tokio::time::interval(reload_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Wait for either a timer tick or SIGHUP.
            #[cfg(unix)]
            tokio::select! {
                _ = interval.tick() => {},
                _ = sighup.recv() => {
                    info!("SIGHUP received — reloading config from {:?}", config_path);
                }
            }
            #[cfg(not(unix))]
            interval.tick().await;

            let new_cfg = match ProxyConfig::load(&config_path) {
                Ok(c) => c,
                Err(e) => {
                    error!("config reload: failed to parse {:?}: {}", config_path, e);
                    continue;
                }
            };

            if let Err(e) = new_cfg.validate() {
                error!("config reload: validation failed: {}; keeping old config", e);
                continue;
            }

            let old_cfg = config_tx.borrow().clone();
            let old_hot = HotFields::from_config(&old_cfg);
            let new_hot = HotFields::from_config(&new_cfg);

            if old_hot == new_hot {
                // Nothing changed in hot fields — skip silent tick.
                continue;
            }

            warn_non_hot_changes(&old_cfg, &new_cfg);

            // Notify log_level change (caller applies it to the tracing filter).
            if old_hot.log_level != new_hot.log_level {
                info!("config reload: log_level → '{}'", new_hot.log_level);
                log_tx.send(new_hot.log_level.clone()).ok();
            }

            // Broadcast the new config snapshot.
            info!("config reload: hot changes applied");
            config_tx.send(Arc::new(new_cfg)).ok();
        }
    });

    (config_rx, log_rx)
}
