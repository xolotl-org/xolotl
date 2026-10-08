#[cfg(feature = "external-websocket")]
use crate::transport::GatewayTransportSecurityTuning;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
use std::fs;
use std::net::IpAddr;
#[cfg(feature = "external-websocket")]
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use xolotl_console::{
    ConsoleAuthConfig, ConsoleTransportSecurityMode, ConsoleWsConfig, DEFAULT_WS_MAX_FRAME_BYTES,
};
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
use xolotl_gateway::GatewayTransportSecurityMode;
#[cfg(feature = "external-websocket")]
use xolotl_gateway_websocket::ExternalWebSocketConfig;

use super::*;
use anyhow::{bail, ensure};
use xolotl_console::{
    HARD_GLOBAL_SESSION_LIMIT, HARD_MAX_WS_CONNECTIONS_PER_SOURCE, HARD_MAX_WS_FRAME_BYTES,
    HARD_MAX_WS_FRAMES_PER_SECOND, HARD_MAX_WS_SUBSCRIPTIONS, MIN_ARGON2_CONCURRENCY,
    MIN_IDLE_TTL_MS, MIN_MAX_SESSIONS_PER_ACCOUNT, MIN_SESSION_TTL_MS, MIN_WS_CONNECTIONS_GLOBAL,
    MIN_WS_CONNECTIONS_PER_ACCOUNT, MIN_WS_IDLE_TIMEOUT, MIN_WS_MAX_BYTES_PER_SECOND,
    MIN_WS_MAX_PENDING_EVENT_BYTES, MIN_WS_SEND_TIMEOUT,
};

#[cfg(feature = "federation-grpc")]
#[test]
fn federation_listener_is_opt_in_and_requires_complete_credentials() -> anyhow::Result<()> {
    let default: XolotlConfig = toml::from_str("")?;
    ensure!(default.server.federation_grpc_addr.is_none());
    let enabled: XolotlConfig = toml::from_str(
        "[server]\nfederation_grpc_addr = '127.0.0.1:9446'\n[federation]\nroot_descriptor_path = '/tmp/root.bin'\n",
    )?;
    ensure!(enabled.federation.validate_credentials().is_err());
    let unknown = toml::from_str::<XolotlConfig>("[federation]\ntrust_all_peers = true\n");
    ensure!(unknown.is_err());
    let invalid_limits = FederationPublisherGrpcConfig {
        max_frame_bytes: 4_096,
        ..FederationPublisherGrpcConfig::default()
    };
    ensure!(invalid_limits.service_config().is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn console_credential_key_file_is_private_and_not_a_symlink() -> anyhow::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir()?;
    let key_path = directory.path().join("credential.key");
    std::fs::write(&key_path, [0x34; 32])?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    let mut console = ConsoleConfig {
        credentials: Some(ConsoleCredentialKeys {
            active_key_id: "current".into(),
            active_key_file: key_path.to_string_lossy().into_owned(),
            previous: Vec::new(),
        }),
        ..Default::default()
    };
    ensure!(
        ConsoleConfig::default()
            .load_credential_sealer(true)
            .is_err()
    );
    ensure!(
        ConsoleConfig::default()
            .load_credential_sealer(false)
            .is_ok()
    );
    ensure!(console.load_credential_sealer(true).is_ok());

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))?;
    ensure!(console.load_credential_sealer(true).is_err());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&key_path, [0x34; 31])?;
    ensure!(console.load_credential_sealer(true).is_err());
    std::fs::write(&key_path, [0x34; 32])?;

    let link = directory.path().join("credential-link.key");
    symlink(&key_path, &link)?;
    console
        .credentials
        .as_mut()
        .context("test console credentials")?
        .active_key_file = link.to_string_lossy().into_owned();
    ensure!(console.load_credential_sealer(true).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn external_pairing_vault_requires_a_private_host_key() -> anyhow::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    ensure!(
        ExternalCredentialsConfig::default()
            .load_key(&ConsoleConfig::default())
            .is_err()
    );
    let directory = tempfile::tempdir()?;
    let key_path = directory.path().join("external.key");
    std::fs::write(&key_path, [0x64; 32])?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    let mut config = ExternalCredentialsConfig {
        key_file: Some(key_path.to_string_lossy().into_owned()),
    };
    ensure!(*config.load_key(&ConsoleConfig::default())? == [0x64; 32]);
    let console_path = directory.path().join("console.key");
    std::fs::write(&console_path, [0x64; 32])?;
    std::fs::set_permissions(&console_path, std::fs::Permissions::from_mode(0o600))?;
    let mut console = ConsoleConfig {
        credentials: Some(ConsoleCredentialKeys {
            active_key_id: "active".into(),
            active_key_file: console_path.to_string_lossy().into_owned(),
            previous: Vec::new(),
        }),
        ..Default::default()
    };
    ensure!(config.load_key(&console).is_err());
    std::fs::write(&console_path, [0x65; 32])?;
    ensure!(config.load_key(&console).is_ok());
    console
        .credentials
        .as_mut()
        .context("test console credentials")?
        .previous = vec![ConsoleDecryptionKey {
        key_id: "old".into(),
        key_file: key_path.to_string_lossy().into_owned(),
    }];
    ensure!(config.load_key(&console).is_err());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))?;
    ensure!(config.load_key(&ConsoleConfig::default()).is_err());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&key_path, [0x64; 31])?;
    ensure!(config.load_key(&ConsoleConfig::default()).is_err());
    std::fs::write(&key_path, [0x64; 32])?;

    let link = directory.path().join("external-link.key");
    symlink(&key_path, &link)?;
    config.key_file = Some(link.to_string_lossy().into_owned());
    ensure!(config.load_key(&ConsoleConfig::default()).is_err());
    Ok(())
}

#[test]
fn explicit_config_path_must_resolve_to_a_file() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing.toml");
    ensure!(XolotlConfig::load_from(&missing, false)?.is_none());
    let error = match XolotlConfig::load_from(&missing, true) {
        Ok(_) => bail!("missing explicit config was accepted"),
        Err(error) => error,
    };
    ensure!(error.to_string().contains("reading config from"));
    ensure!(XolotlConfig::load_from(Path::new(""), true).is_err());
    ensure!(XolotlConfig::load_from(directory.path(), true).is_err());

    let configured = directory.path().join("configured.toml");
    std::fs::write(&configured, "[storage]\nkind = 'memory'\n")?;
    let config = XolotlConfig::load_from(&configured, true)?
        .ok_or_else(|| anyhow::anyhow!("explicit config was ignored"))?;
    ensure!(config.storage.kind == StorageKind::Memory);
    Ok(())
}

#[cfg(unix)]
#[test]
fn config_path_preserves_non_unicode_file_names() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStringExt;

    let directory = tempfile::tempdir()?;
    let configured = directory.path().join(std::ffi::OsString::from_vec(
        b"configured-\xff.toml".to_vec(),
    ));
    std::fs::write(&configured, "[storage]\nkind = 'memory'\n")?;
    let config = XolotlConfig::load_from(&configured, true)?
        .ok_or_else(|| anyhow::anyhow!("explicit config was ignored"))?;
    ensure!(config.storage.kind == StorageKind::Memory);
    Ok(())
}

#[test]
fn observations_require_explicit_finite_valid_budgets() -> anyhow::Result<()> {
    let default: XolotlConfig = toml::from_str("")?;
    ensure!(default.storage.observations.is_none());
    let configured: XolotlConfig = toml::from_str(
        "[storage.observations]\nmax_records = 2\nmax_encoded_bytes = 4096\nmax_record_bytes = 1024",
    )?;
    let limits = configured
        .storage
        .observations
        .ok_or_else(|| anyhow::anyhow!("configured observation budgets missing"))?
        .limits()?;
    ensure!(limits.max_records.get() == 2);
    let invalid: XolotlConfig = toml::from_str(
        "[storage.observations]\nmax_records = 2\nmax_encoded_bytes = 512\nmax_record_bytes = 1024",
    )?;
    ensure!(
        invalid
            .storage
            .observations
            .ok_or_else(|| anyhow::anyhow!("invalid observation budgets missing"))?
            .limits()
            .is_err()
    );
    ensure!(toml::from_str::<XolotlConfig>(
        "[storage.observations]\nmax_records = 0\nmax_encoded_bytes = 4096\nmax_record_bytes = 1024",
    ).is_err());
    ensure!(toml::from_str::<XolotlConfig>("[storage.observations]\nmax_records = 2").is_err());
    Ok(())
}

#[test]
fn storage_history_has_closed_config_values_and_current_only_default() -> anyhow::Result<()> {
    let default: XolotlConfig = toml::from_str("")?;
    ensure!(default.storage.kind == StorageKind::Redb);
    ensure!(default.storage.state_history == StorageHistoryMode::CurrentOnly);
    ensure!(default.storage.source_stream_limit.get() == 4096);
    ensure!(default.storage.source_retention_limit.get() == 65_536);
    ensure!(default.storage.federation_publish_id_limit.get() == 65_536);
    ensure!(default.kernel.max_handle_slots.get() == 65_536);
    let limited: XolotlConfig = toml::from_str("[kernel]\nmax_handle_slots = 32")?;
    ensure!(limited.kernel.max_handle_slots.get() == 32);
    ensure!(toml::from_str::<XolotlConfig>("[kernel]\nmax_handle_slots = 0").is_err());
    let small: XolotlConfig = toml::from_str("[storage]\nsource_stream_limit = 2")?;
    ensure!(small.storage.source_stream_limit.get() == 2);
    ensure!(toml::from_str::<XolotlConfig>("[storage]\nsource_stream_limit = 0").is_err());
    let retained: XolotlConfig = toml::from_str("[storage]\nsource_retention_limit = 2")?;
    ensure!(retained.storage.source_retention_limit.get() == 2);
    ensure!(toml::from_str::<XolotlConfig>("[storage]\nsource_retention_limit = 0").is_err());
    let publish: XolotlConfig = toml::from_str("[storage]\nfederation_publish_id_limit = 2")?;
    ensure!(publish.storage.federation_publish_id_limit.get() == 2);
    ensure!(toml::from_str::<XolotlConfig>("[storage]\nfederation_publish_id_limit = 0").is_err());
    let memory: XolotlConfig = toml::from_str("[storage]\nkind = 'memory'")?;
    ensure!(memory.storage.kind == StorageKind::Memory);
    let full: XolotlConfig = toml::from_str("[storage]\nstate_history = 'full'")?;
    ensure!(full.storage.state_history == StorageHistoryMode::Full);
    ensure!(full.storage.history_maintenance()?.is_none());
    let current: XolotlConfig = toml::from_str("[storage]\nstate_history = 'current_only'")?;
    ensure!(current.storage.state_history == StorageHistoryMode::CurrentOnly);
    ensure!(current.storage.history_maintenance()?.is_none());
    let managed: XolotlConfig = toml::from_str(
        "[storage]\nstate_history = 'full'\n[storage.history_maintenance]\nretain_for_ms = 86_400_000",
    )?;
    let policy = managed
        .storage
        .history_maintenance()?
        .ok_or_else(|| anyhow::anyhow!("history maintenance policy missing"))?;
    ensure!(policy.retain_for_ms.get() == 86_400_000);
    ensure!(policy.max_attempts_per_tick.get() == 16);
    ensure!(policy.max_batches_per_tick.get() == 4);
    let ignored: XolotlConfig = toml::from_str("[storage.history_maintenance]\nretain_for_ms = 1")?;
    ensure!(ignored.storage.history_maintenance().is_err());
    ensure!(
        toml::from_str::<XolotlConfig>(
            "[storage]\nstate_history = 'full'\n[storage.history_maintenance]\ninterval_ms = 100"
        )
        .is_err()
    );
    for invalid in [
        "retain_for_ms = 0",
        "retain_for_ms = 1\nmax_batches_per_tick = 0",
        "retain_for_ms = 1\nencoded_bytes_per_batch = 0",
    ] {
        let text =
            format!("[storage]\nstate_history = 'full'\n[storage.history_maintenance]\n{invalid}");
        ensure!(toml::from_str::<XolotlConfig>(&text).is_err());
    }
    let too_much: XolotlConfig = toml::from_str(
        "[storage]\nstate_history = 'full'\n[storage.history_maintenance]\nretain_for_ms = 1\nevents_per_batch = 4097",
    )?;
    ensure!(too_much.storage.history_maintenance().is_err());
    let too_often: XolotlConfig = toml::from_str(
        "[storage]\nstate_history = 'full'\n[storage.history_maintenance]\nretain_for_ms = 1\ninterval_ms = 999",
    )?;
    ensure!(too_often.storage.history_maintenance().is_err());
    ensure!(toml::from_str::<XolotlConfig>("[storage]\nstate_history = 'bounded'").is_err());
    ensure!(toml::from_str::<XolotlConfig>("[storage]\nkind = 'other'").is_err());
    Ok(())
}

#[test]
fn sourced_absence_limits_are_bounded_by_default_and_explicitly_unlimited() -> anyhow::Result<()> {
    let default: XolotlConfig = toml::from_str("")?;
    ensure!(default.storage.absence_limits() == xolotl_state::AbsenceLimits::default());
    let bounded: XolotlConfig =
        toml::from_str("[storage]\nabsence_record_limit = 0\nabsence_encoded_byte_limit = 8192")?;
    ensure!(bounded.storage.absence_record_limit == Some(0));
    ensure!(bounded.storage.absence_encoded_byte_limit == Some(8192));
    let unlimited: XolotlConfig = toml::from_str(
        "[storage]\nabsence_record_limit = 'unlimited'\nabsence_encoded_byte_limit = 'unlimited'",
    )?;
    ensure!(unlimited.storage.absence_record_limit.is_none());
    ensure!(unlimited.storage.absence_encoded_byte_limit.is_none());
    for invalid in ["-1", "'automatic'", "false"] {
        ensure!(
            toml::from_str::<XolotlConfig>(&format!("[storage]\nabsence_record_limit = {invalid}"))
                .is_err()
        );
    }
    Ok(())
}

macro_rules! assert {
    ($condition:expr $(,)?) => {
        anyhow::ensure!($condition, "assertion failed: {}", stringify!($condition));
    };
    ($condition:expr, $($arg:tt)+) => {
        anyhow::ensure!($condition, $($arg)+);
    };
}

macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => anyhow::ensure!(
                left == right,
                "assertion failed: left != right\nleft: {left:?}\nright: {right:?}"
            ),
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        anyhow::ensure!($left == $right, $($arg)+);
    };
}

fn assert_config_rejects_unknown_field(toml: &str, field: &str) -> anyhow::Result<()> {
    let err = match toml::from_str::<XolotlConfig>(toml) {
        Ok(config) => bail!("expected unknown-field rejection, got {config:?}"),
        Err(error) => error,
    };
    let message = err.to_string();
    assert!(
        message.contains("unknown field") && message.contains(field),
        "unexpected error for {field}: {message}"
    );
    Ok(())
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn temp_config_file(name: &str, contents: &[u8]) -> anyhow::Result<String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "xolotl-config-test-{}-{nanos}-{name}",
        std::process::id()
    ));
    fs::write(&path, contents)
        .with_context(|| format!("writing temporary config file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(path.to_string_lossy().into_owned())
}

#[test]
fn console_tuning_defaults_match_runtime_defaults() -> anyhow::Result<()> {
    let config = ConsoleConfig::default();
    assert_eq!(
        config.max_concurrent_calls,
        xolotl_console::ConsoleConfig::default().max_concurrent_calls
    );
    assert_eq!(
        config.max_concurrent_authentications,
        xolotl_console::ConsoleConfig::default().max_concurrent_authentications
    );
    assert_eq!(
        config.request_body_timeout_ms,
        xolotl_console::http::DEFAULT_HTTP_REQUEST_BODY_TIMEOUT.as_millis() as u64
    );
    let custom: ConsoleConfig = toml::from_str("request_body_timeout_ms = 2500")?;
    assert_eq!(custom.request_body_timeout_ms, 2500);
    let parsed: ConsoleConfig = toml::from_str(
        "[queries]\nmax_state_list_limit = 7\nmax_process_limit = 3\nmax_page_bytes = 8192\n",
    )?;
    assert_eq!(parsed.queries.max_state_list_limit, 7);
    assert_eq!(parsed.queries.max_process_limit, 3);
    assert_eq!(parsed.queries.max_page_bytes, 8192);
    assert_eq!(parsed.ws.max_frame_bytes, DEFAULT_WS_MAX_FRAME_BYTES);
    let auth: ConsoleAuthConfig = ConsoleAuthTuning::default().into();
    let default_auth = ConsoleAuthConfig::default();
    assert_eq!(auth.session_ttl_ms, default_auth.session_ttl_ms);
    assert_eq!(auth.idle_ttl_ms, default_auth.idle_ttl_ms);
    assert_eq!(
        ConsoleAuthTuning::default().session_policy()?,
        xolotl_console::session_store::ConsoleSessionPolicy::default()
    );
    assert_eq!(auth.argon2_concurrency, default_auth.argon2_concurrency);
    assert_eq!(
        auth.max_external_verifications,
        default_auth.max_external_verifications
    );

    let ws: ConsoleWsConfig = ConsoleWsTuning::default().into();
    let default_ws = ConsoleWsConfig::default();
    assert_eq!(ws.max_frame_bytes, default_ws.max_frame_bytes);
    assert_eq!(ws.max_connections_global, default_ws.max_connections_global);
    assert_eq!(
        ws.max_connections_per_source,
        default_ws.max_connections_per_source
    );
    assert_eq!(
        ws.max_connections_per_account,
        default_ws.max_connections_per_account
    );
    assert_eq!(ws.idle_timeout, default_ws.idle_timeout);
    assert_eq!(ws.max_frames_per_second, default_ws.max_frames_per_second);
    assert_eq!(ws.max_bytes_per_second, default_ws.max_bytes_per_second);
    assert_eq!(ws.max_subscriptions, default_ws.max_subscriptions);
    assert_eq!(
        ws.max_pending_event_bytes,
        default_ws.max_pending_event_bytes
    );
    assert_eq!(ws.send_timeout, default_ws.send_timeout);
    Ok(())
}

#[test]
fn console_tuning_clamps_unreasonable_values() -> anyhow::Result<()> {
    let tuning = ConsoleAuthTuning {
        session_ttl_ms: 1,
        idle_ttl_ms: -1,
        max_sessions_per_account: 0,
        global_session_limit: usize::MAX,
        argon2_concurrency: 0,
        max_external_verifications: usize::MAX,
        challenges: xolotl_console::ConsoleChallengeConfig::default(),
        webauthn: ConsoleWebAuthnTuning::default(),
        mfa: xolotl_console::mfa::ConsoleMfaConfig::default(),
    };
    let policy = tuning.session_policy()?;
    let auth: ConsoleAuthConfig = tuning.into();
    assert_eq!(auth.session_ttl_ms, MIN_SESSION_TTL_MS);
    assert_eq!(auth.idle_ttl_ms, MIN_IDLE_TTL_MS);
    assert_eq!(policy.per_account(), MIN_MAX_SESSIONS_PER_ACCOUNT);
    assert_eq!(policy.domain(), HARD_GLOBAL_SESSION_LIMIT);
    assert_eq!(auth.argon2_concurrency, MIN_ARGON2_CONCURRENCY);
    assert_eq!(auth.max_external_verifications, 256);

    let ws: ConsoleWsConfig = ConsoleWsTuning {
        max_frame_bytes: usize::MAX,
        max_connections_global: 0,
        max_connections_per_source: usize::MAX,
        max_connections_per_account: 0,
        idle_timeout_secs: 0,
        max_frames_per_second: usize::MAX,
        max_bytes_per_second: 1,
        max_subscriptions: usize::MAX,
        max_pending_event_bytes: 0,
        send_timeout_ms: 1,
    }
    .into();
    assert_eq!(ws.max_frame_bytes, HARD_MAX_WS_FRAME_BYTES);
    assert_eq!(ws.max_connections_global, MIN_WS_CONNECTIONS_GLOBAL);
    assert_eq!(
        ws.max_connections_per_source,
        HARD_MAX_WS_CONNECTIONS_PER_SOURCE
    );
    assert_eq!(
        ws.max_connections_per_account,
        MIN_WS_CONNECTIONS_PER_ACCOUNT
    );
    assert_eq!(ws.idle_timeout, MIN_WS_IDLE_TIMEOUT);
    assert_eq!(ws.max_frames_per_second, HARD_MAX_WS_FRAMES_PER_SECOND);
    assert_eq!(ws.max_bytes_per_second, MIN_WS_MAX_BYTES_PER_SECOND);
    assert_eq!(ws.max_subscriptions, HARD_MAX_WS_SUBSCRIPTIONS);
    assert_eq!(ws.max_pending_event_bytes, MIN_WS_MAX_PENDING_EVENT_BYTES);
    assert_eq!(ws.send_timeout, MIN_WS_SEND_TIMEOUT);
    Ok(())
}

#[test]
fn console_submission_retry_cadence_is_bounded_and_independent_of_result_retention()
-> anyhow::Result<()> {
    let default = ConsoleConfig::default();
    assert_eq!(
        default.submission_retry_epoch_period()?,
        Duration::from_secs(900)
    );
    let parsed: ConsoleConfig = toml::from_str(
        "submission_retry_epoch_ms = 120000\n[runtime.executions]\nretention_ms = 7\n",
    )?;
    assert_eq!(
        parsed.submission_retry_epoch_period()?,
        Duration::from_secs(120)
    );
    assert_eq!(parsed.runtime.executions.retention_ms, 7);
    for millis in [1, 86_400_000] {
        let accepted: ConsoleConfig =
            toml::from_str(&format!("submission_retry_epoch_ms = {millis}"))?;
        assert_eq!(
            accepted.submission_retry_epoch_period()?,
            Duration::from_millis(millis)
        );
    }
    for millis in [0, 86_400_001, u64::MAX] {
        assert!(
            toml::from_str::<ConsoleConfig>(&format!("submission_retry_epoch_ms = {millis}"))
                .is_err()
        );
        let native = ConsoleConfig {
            submission_retry_epoch_ms: millis,
            ..Default::default()
        };
        assert!(native.submission_retry_epoch_period().is_err());
    }
    Ok(())
}

#[test]
fn config_file_accepts_console_transport_security() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_proto = true
honor_x_forwarded_host = true
honor_x_forwarded_for = true
"#,
    )?;

    let transport = cfg
        .console
        .transport_security
        .to_console_transport_security_config()?;
    assert_eq!(
        transport.mode,
        ConsoleTransportSecurityMode::TrustedReverseProxy
    );
    assert_eq!(
        transport.trusted_proxy.peers,
        vec!["127.0.0.1".parse::<IpAddr>()?]
    );
    Ok(())
}

#[test]
fn console_transport_security_requires_proxy_peer() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
"#,
    )?;

    let err = match cfg
        .console
        .transport_security
        .to_console_transport_security_config()
    {
        Ok(transport) => bail!("expected proxy peer rejection, got {transport:?}"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("trusted_proxy_peers"));
    Ok(())
}

#[test]
fn console_plain_listener_rejects_production_tls() -> anyhow::Result<()> {
    let cfg = toml::from_str::<XolotlConfig>(
        r#"
[console.transport_security]
mode = "production_tls"
"#,
    )?;

    let err = match cfg
        .console
        .transport_security
        .validate_plain_listener("console", "127.0.0.1:9000")
    {
        Ok(listener) => bail!("expected production TLS rejection, got {listener:?}"),
        Err(error) => error,
    };
    let message = err.to_string();
    assert!(message.contains("production_tls requires a TLS listener"));
    Ok(())
}

#[test]
fn console_local_trusted_requires_loopback_listener() -> anyhow::Result<()> {
    let cfg = toml::from_str::<XolotlConfig>(
        r#"
[console.transport_security]
mode = "local_trusted"
"#,
    )?;

    let err = match cfg
        .console
        .transport_security
        .validate_plain_listener("console", "0.0.0.0:9000")
    {
        Ok(listener) => bail!("expected local trusted rejection, got {listener:?}"),
        Err(error) => error,
    };
    let message = err.to_string();
    assert!(message.contains("local_trusted requires a loopback listen address"));
    Ok(())
}

#[test]
fn config_file_accepts_explicit_console_unsafe_transport() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[console.transport_security]
mode = "unsafe_plaintext"
unsafe_relaxations = ["ignore_origin_port"]
"#,
    )?;

    let transport = cfg
        .console
        .transport_security
        .to_console_transport_security_config()?;
    assert_eq!(
        transport.mode,
        ConsoleTransportSecurityMode::UnsafePlaintext
    );
    assert!(transport.is_unsafe());
    assert!(transport.ignore_origin_port());
    Ok(())
}

#[test]
fn config_file_rejects_unknown_bootstrap_fields() -> anyhow::Result<()> {
    assert_config_rejects_unknown_field(
        r#"
unknown_section = true
"#,
        "unknown_section",
    )?;
    assert_config_rejects_unknown_field(
        r#"
[server]
unknown_addr = "127.0.0.1:9100"
"#,
        "unknown_addr",
    )?;
    assert_config_rejects_unknown_field(
        r#"
[console.ws]
max_frame_bytez = 1024
"#,
        "max_frame_bytez",
    )?;
    Ok(())
}

#[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
#[test]
fn example_config_uses_declared_fields() -> anyhow::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../xolotl.toml.example");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading example config {}", path.display()))?;
    toml::from_str::<XolotlConfig>(&content)
        .with_context(|| format!("parsing example config {}", path.display()))?;
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn gateway_transport_security_defaults_to_loopback_only() -> anyhow::Result<()> {
    let cfg = GatewayTransportSecurityTuning::default();
    let security = cfg
        .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
        .context("loopback listener should be accepted")?;
    assert_eq!(
        security.config.mode,
        GatewayTransportSecurityMode::LocalTrusted
    );
    assert_eq!(
        security.listen_addr,
        "127.0.0.1:9200".parse::<SocketAddr>()?
    );

    let err = match cfg.validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200") {
        Ok(_security) => bail!("expected non-loopback listener rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("loopback"));
    Ok(())
}

#[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
#[test]
fn config_file_accepts_external_gateway_listeners() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway.grpc]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
provider_max_inline_result_bytes = 0
source_max_in_flight_commands = 0
source_command_max_inline_result_bytes = 0
source_command_rate_limit_window_ms = 0
source_command_rate_limit_max = 0

[external_gateway.grpc.transport_security]
mode = "local_trusted"

[external_gateway.websocket]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
provider_max_inline_result_bytes = 0
source_max_in_flight_commands = 0
source_command_max_inline_result_bytes = 0
source_command_rate_limit_window_ms = 0
source_command_rate_limit_max = 0

[external_gateway.websocket.transport]
max_frame_bytes = 0
first_frame_timeout_ms = 0
idle_timeout_ms = 0
max_connections = 0

[external_gateway.websocket.transport_security]
mode = "local_trusted"
"#,
    )?;

    assert_eq!(
        cfg.server.external_grpc_addr.as_deref(),
        Some("127.0.0.1:9444")
    );
    assert_eq!(
        cfg.server.external_websocket_addr.as_deref(),
        Some("127.0.0.1:9200")
    );

    let grpc = cfg.external_gateway.grpc.clone().bounded();
    assert_eq!(
        grpc.session_limits(),
        ExternalGatewaySessionLimits::default()
    );

    let websocket = cfg.external_gateway.websocket.clone().bounded();
    assert_eq!(
        websocket.session_limits(),
        ExternalGatewaySessionLimits::default()
    );
    let ws_transport: ExternalWebSocketConfig = websocket.transport.into();
    assert_eq!(ws_transport, ExternalWebSocketConfig::default());

    #[cfg(feature = "external-grpc")]
    {
        let listener = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener(
                "external gRPC gateway",
                cfg.server
                    .external_grpc_addr
                    .as_deref()
                    .context("external_grpc_addr should be configured")?,
            )
            .context("gRPC listener should be accepted")?;
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::LocalTrusted
        );
    }

    let listener = cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener(
            "external WebSocket gateway",
            cfg.server
                .external_websocket_addr
                .as_deref()
                .context("external_websocket_addr should be configured")?,
        )
        .context("WebSocket listener should be accepted")?;
    assert_eq!(
        listener.config.mode,
        GatewayTransportSecurityMode::LocalTrusted
    );
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn config_file_accepts_external_gateway_trusted_proxy_transport_security() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_for = true
"#,
    )?;

    let security = cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
        .context("trusted proxy listener should be accepted")?;
    assert_eq!(
        security.config.mode,
        GatewayTransportSecurityMode::TrustedReverseProxy
    );
    assert_eq!(
        security.config.trusted_proxy.peers,
        vec!["127.0.0.1".parse::<IpAddr>()?]
    );
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn external_gateway_plain_listener_trusted_proxy_requires_peer() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
"#,
    )?;

    let err = match cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
    {
        Ok(_security) => bail!("expected trusted proxy peer rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("trusted_proxy_peers"));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn external_gateway_grpc_trusted_proxy_requires_peer() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.grpc.transport_security]
mode = "trusted_reverse_proxy"
"#,
    )?;

    let err = match cfg
        .external_gateway
        .grpc
        .transport_security
        .validate_grpc_listener("external gRPC gateway", "0.0.0.0:9444")
    {
        Ok(_listener) => bail!("expected trusted proxy peer rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("trusted_proxy_peers"));
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn external_gateway_disabled_for_test_is_rejected_outside_tests() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.websocket.transport_security]
mode = "disabled_for_test"
"#,
    )?;

    let err = match cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener_inner("external WebSocket gateway", "127.0.0.1:9200", false)
    {
        Ok(_security) => bail!("expected disabled_for_test rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("only valid in tests"));
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn external_gateway_plain_listener_tls_modes_fail_closed() -> anyhow::Result<()> {
    let cert = temp_config_file("cert.pem", b"certificate")?;
    let key = temp_config_file("key.pem", b"private-key")?;
    let root = temp_config_file("client-ca.pem", b"client-ca")?;
    let cfg: XolotlConfig = toml::from_str(&format!(
        r#"
[external_gateway.websocket.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
    ))?;

    let err = match cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
    {
        Ok(_security) => bail!("expected production TLS plain-listener rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("requires a TLS listener"));

    let cfg: XolotlConfig = toml::from_str(&format!(
        r#"
[external_gateway.websocket.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#,
    ))?;

    let err = match cfg
        .external_gateway
        .websocket
        .transport_security
        .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
    {
        Ok(_security) => bail!("expected mutual TLS plain-listener rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("requires a TLS listener"));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn external_gateway_grpc_tls_modes_require_material() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
"#,
    )?;

    let err = match cfg
        .external_gateway
        .grpc
        .transport_security
        .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
    {
        Ok(_listener) => bail!("expected certificate material rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("certificate_chain_path"));

    let cert = temp_config_file("cert.pem", b"certificate")?;
    let key = temp_config_file("key.pem", b"private-key")?;
    let cfg: XolotlConfig = toml::from_str(&format!(
        r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
    ))?;

    let err = match cfg
        .external_gateway
        .grpc
        .transport_security
        .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
    {
        Ok(_listener) => bail!("expected client trust roots rejection"),
        Err(error) => error,
    };
    assert!(err.to_string().contains("client_trust_roots"));
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn external_gateway_grpc_tls_modes_load_certificate_material() -> anyhow::Result<()> {
    let cert = temp_config_file("cert.pem", b"certificate")?;
    let key = temp_config_file("key.pem", b"private-key")?;
    let cfg: XolotlConfig = toml::from_str(&format!(
        r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#
    ))?;

    let listener = cfg
        .external_gateway
        .grpc
        .transport_security
        .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
        .context("production TLS listener should load certificate material")?;
    assert_eq!(
        listener.config.mode,
        GatewayTransportSecurityMode::ProductionTls
    );
    assert!(listener.tls.is_some());
    Ok(())
}

#[cfg(all(unix, feature = "external-grpc"))]
#[test]
fn grpc_tls_private_key_file_must_be_private_regular_and_bounded() -> anyhow::Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir()?;
    let key = directory.path().join("server-key.pem");
    fs::write(&key, b"private-key")?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    let path = key.to_str().context("UTF-8 key path")?;
    ensure!(read_private_pem_file(path, "gRPC TLS key").is_ok());

    fs::set_permissions(&key, fs::Permissions::from_mode(0o644))?;
    ensure!(read_private_pem_file(path, "gRPC TLS key").is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;

    let link = directory.path().join("server-key-link.pem");
    symlink(&key, &link)?;
    ensure!(
        read_private_pem_file(link.to_str().context("UTF-8 link path")?, "gRPC TLS key").is_err()
    );

    fs::write(&key, vec![b'a'; 64 * 1024 + 1])?;
    ensure!(read_private_pem_file(path, "gRPC TLS key").is_err());
    ensure!(read_private_pem_file("relative-key.pem", "gRPC TLS key").is_err());
    Ok(())
}

#[cfg(feature = "external-grpc")]
#[test]
fn external_gateway_grpc_mtls_requires_and_loads_client_roots() -> anyhow::Result<()> {
    let cert = temp_config_file("cert.pem", b"certificate")?;
    let key = temp_config_file("key.pem", b"private-key")?;
    let root = temp_config_file("client-ca.pem", b"client-ca")?;
    let cfg: XolotlConfig = toml::from_str(&format!(
        r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#
    ))?;

    let listener = cfg
        .external_gateway
        .grpc
        .transport_security
        .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
        .context("mutual TLS listener should load certificate material")?;
    assert_eq!(
        listener.config.mode,
        GatewayTransportSecurityMode::MutualTls
    );
    let tls = listener
        .tls
        .context("mutual TLS material should be present")?;
    assert!(!tls.client_trust_roots_pem.is_empty());
    Ok(())
}

#[test]
fn config_file_accepts_console_auth_and_ws_tuning() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[console.auth]
session_ttl_ms = 120000
idle_ttl_ms = 60000
max_sessions_per_account = 2
global_session_limit = 64
argon2_concurrency = 2
max_external_verifications = 8

[console.auth.mfa]
issuer = "Operations"
enrollment_ttl_ms = 120000
recent_auth_ttl_ms = 90000

[console.auth.mfa.totp]
algorithm = "SHA512"
digits = 8
period_seconds = 60
clock_skew_steps = 2

[console.ws]
max_frame_bytes = 32768
max_connections_global = 8
max_connections_per_source = 4
max_connections_per_account = 2
idle_timeout_secs = 60
max_frames_per_second = 16
max_bytes_per_second = 65536
max_subscriptions = 4
max_pending_event_bytes = 65536
send_timeout_ms = 250
"#,
    )?;

    let policy = cfg.console.auth.session_policy()?;
    let auth: ConsoleAuthConfig = cfg.console.auth.into();
    assert_eq!(auth.session_ttl_ms, 120_000);
    assert_eq!(policy.per_account(), 2);
    assert_eq!(auth.max_external_verifications, 8);
    assert_eq!(auth.mfa.issuer, "Operations");
    assert_eq!(auth.mfa.enrollment_ttl_ms, 120_000);
    assert_eq!(auth.mfa.recent_auth_ttl_ms, 90_000);
    assert!(auth.mfa.install_totp);
    assert!(matches!(
        auth.mfa.totp.algorithm,
        xolotl_console::mfa::TotpAlgorithm::Sha512
    ));
    assert_eq!(auth.mfa.totp.digits, 8);
    assert_eq!(auth.mfa.totp.period_seconds, 60);
    assert_eq!(auth.mfa.totp.clock_skew_steps, 2);

    let ws: ConsoleWsConfig = cfg.console.ws.into();
    assert_eq!(ws.max_frame_bytes, 32_768);
    assert_eq!(ws.max_connections_global, 8);
    assert_eq!(ws.idle_timeout, Duration::from_secs(60));
    assert_eq!(ws.max_pending_event_bytes, 65_536);
    assert_eq!(ws.send_timeout, Duration::from_millis(250));
    Ok(())
}

#[test]
fn console_mfa_builtin_installation_is_explicit_in_toml() -> anyhow::Result<()> {
    for (source, expected) in [
        ("", true),
        ("[console.auth.mfa]", true),
        ("[console.auth.mfa]\ninstall_totp = true", true),
        ("[console.auth.mfa]\ninstall_totp = false", false),
    ] {
        let cfg: XolotlConfig = toml::from_str(source)?;
        let auth: ConsoleAuthConfig = cfg.console.auth.into();
        assert_eq!(auth.mfa.install_totp, expected);
        assert!(auth.mfa.providers.is_empty());
    }
    let cfg: XolotlConfig = toml::from_str(
        r#"
[console.auth.mfa]
install_totp = false

[console.auth.mfa.totp]
digits = 0
period_seconds = 0
clock_skew_steps = 255
"#,
    )?;
    let auth: ConsoleAuthConfig = cfg.console.auth.into();
    assert!(!auth.mfa.install_totp);
    assert_eq!(auth.mfa.totp.digits, 0);
    assert_eq!(auth.mfa.totp.period_seconds, 0);
    assert_eq!(auth.mfa.totp.clock_skew_steps, u8::MAX);
    Ok(())
}

#[test]
fn console_mfa_json_installation_matches_daemon_tuning() -> anyhow::Result<()> {
    for (value, expected) in [
        (serde_json::json!({}), true),
        (serde_json::json!({"mfa":{}}), true),
        (serde_json::json!({"mfa":{"install_totp":false}}), false),
    ] {
        let tuning: ConsoleAuthTuning = serde_json::from_value(value)?;
        let auth: ConsoleAuthConfig = tuning.into();
        assert_eq!(auth.mfa.install_totp, expected);
        assert!(auth.mfa.providers.is_empty());
    }
    for invalid in [
        "[console.auth.mfa]\ninstall_totp = 0",
        "[console.auth.mfa]\ninstall_topt = false",
        "[console.auth.mfa]\nproviders = []",
    ] {
        assert!(toml::from_str::<XolotlConfig>(invalid).is_err());
    }
    Ok(())
}

#[test]
fn console_provider_usage_survives_toml_and_json_tuning() -> anyhow::Result<()> {
    use xolotl_console::mfa::MfaProviderUsage;
    for allow_enrollment in [false, true] {
        for allow_authentication in [false, true] {
            let source = format!(
                "[console.auth.mfa.provider_usage.totp]\nallow_enrollment = {allow_enrollment}\nallow_authentication = {allow_authentication}"
            );
            let config: XolotlConfig = toml::from_str(&source)?;
            let serialized = serde_json::to_value(&config.console.auth.mfa)?;
            let decoded: ConsoleAuthTuning = serde_json::from_value(serde_json::json!({
                "mfa": serialized,
            }))?;
            let auth: ConsoleAuthConfig = decoded.into();
            assert_eq!(
                auth.mfa.provider_usage.get("totp"),
                Some(&MfaProviderUsage {
                    allow_enrollment,
                    allow_authentication,
                })
            );
        }
    }
    let partial: XolotlConfig =
        toml::from_str("[console.auth.mfa.provider_usage.device]\nallow_enrollment = false")?;
    let auth: ConsoleAuthConfig = partial.console.auth.into();
    assert_eq!(
        auth.mfa.provider_usage.get("device"),
        Some(&MfaProviderUsage {
            allow_enrollment: false,
            allow_authentication: true,
        })
    );
    for invalid in [
        "[console.auth.mfa.provider_usage.totp]\nallow_enrollment = 1",
        "[console.auth.mfa.provider_usage.totp]\nallow_authentication = 'false'",
        "[console.auth.mfa.provider_usage.totp]\nallow_authentcation = false",
    ] {
        assert!(toml::from_str::<XolotlConfig>(invalid).is_err());
    }
    Ok(())
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
#[test]
fn source_command_limit_is_global_and_positive() -> anyhow::Result<()> {
    assert_eq!(
        ExternalGatewayConfig::default().source_command_limit.get(),
        65_536
    );
    for source in ["", "[external_gateway]"] {
        let config: XolotlConfig = toml::from_str(source)?;
        assert_eq!(config.external_gateway.source_command_limit.get(), 65_536);
    }
    for limit in [1, 17, 65_536, 65_537] {
        let source = format!("[external_gateway]\nsource_command_limit = {limit}");
        let config: XolotlConfig = toml::from_str(&source)?;
        assert_eq!(config.external_gateway.source_command_limit.get(), limit);
    }
    for value in ["0", "-1", "1.5", "'17'", "true"] {
        let source = format!("[external_gateway]\nsource_command_limit = {value}");
        assert!(toml::from_str::<XolotlConfig>(&source).is_err());
    }
    #[cfg(feature = "external-grpc")]
    assert!(
        toml::from_str::<XolotlConfig>("[external_gateway.grpc]\nsource_command_limit = 17")
            .is_err()
    );
    #[cfg(feature = "external-websocket")]
    assert!(
        toml::from_str::<XolotlConfig>("[external_gateway.websocket]\nsource_command_limit = 17")
            .is_err()
    );
    Ok(())
}

#[cfg(feature = "external-websocket")]
#[test]
fn external_gateway_websocket_transport_config_is_bounded() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.websocket.transport]
max_frame_bytes = 0
first_frame_timeout_ms = 0
idle_timeout_ms = 0
max_connections = 0
"#,
    )?;

    let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
    assert_eq!(ws, ExternalWebSocketConfig::default());

    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.websocket.transport]
max_frame_bytes = 999999999999
first_frame_timeout_ms = 999999999999
idle_timeout_ms = 999999999999
max_connections = 999999999999
"#,
    )?;
    let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
    assert_eq!(
        ws.max_frame_bytes,
        xolotl_gateway_websocket::HARD_MAX_FRAME_BYTES
    );
    assert_eq!(
        ws.first_frame_timeout_ms,
        xolotl_gateway_websocket::HARD_FIRST_FRAME_TIMEOUT_MS
    );
    assert_eq!(
        ws.idle_timeout_ms,
        xolotl_gateway_websocket::HARD_IDLE_TIMEOUT_MS
    );
    assert_eq!(
        ws.max_connections,
        xolotl_gateway_websocket::HARD_MAX_CONNECTIONS
    );
    Ok(())
}

#[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
#[test]
fn external_gateway_limits_are_bounded() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.grpc]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
provider_max_inline_result_bytes = 999999999999
source_max_in_flight_commands = 999999999999
source_command_max_inline_result_bytes = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999

[external_gateway.websocket]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
provider_max_inline_result_bytes = 999999999999
source_max_in_flight_commands = 999999999999
source_command_max_inline_result_bytes = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999
"#,
    )?;

    let grpc = cfg.external_gateway.grpc.bounded();
    assert_eq!(
        grpc.session_limits(),
        hard_external_gateway_session_limits()
    );

    let websocket = cfg.external_gateway.websocket.bounded();
    assert_eq!(
        websocket.session_limits(),
        hard_external_gateway_session_limits()
    );
    Ok(())
}

#[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
#[test]
fn source_maintenance_is_bounded() -> anyhow::Result<()> {
    let cfg: XolotlConfig = toml::from_str(
        r#"
[external_gateway.source_maintenance]
interval_ms = 0
max_batches_per_tick = 999999

"#,
    )?;
    let maintenance = cfg.external_gateway.source_maintenance.bounded();
    assert_eq!(
        maintenance.interval_ms,
        DEFAULT_SOURCE_MAINTENANCE_INTERVAL_MS
    );
    assert_eq!(
        maintenance.max_batches_per_tick,
        HARD_SOURCE_MAINTENANCE_BATCHES_PER_TICK
    );
    let other = SourceMaintenanceConfig {
        interval_ms: u64::MAX,
        max_batches_per_tick: 0,
    }
    .bounded();
    assert_eq!(other.interval_ms, HARD_SOURCE_MAINTENANCE_INTERVAL_MS);
    assert_eq!(
        other.max_batches_per_tick,
        DEFAULT_SOURCE_MAINTENANCE_BATCHES_PER_TICK
    );
    Ok(())
}

#[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
fn hard_external_gateway_session_limits() -> ExternalGatewaySessionLimits {
    ExternalGatewaySessionLimits {
        source_dedupe_window_ms: HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS,
        provider_max_in_flight_invocations: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS,
        provider_max_in_flight_per_identity: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY,
        provider_max_in_flight_per_effect: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT,
        provider_max_inline_result_bytes: HARD_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES,
        source_max_in_flight_commands: HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
        source_command_max_inline_result_bytes:
            HARD_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES,
        source_command_rate_limit_window_ms: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS,
        source_command_rate_limit_max: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX,
    }
}
