use anyhow::{Result, ensure};
use xolotl_gateway::external::{
    EnvelopeAad, ExternalCredential, validate_secure_external_envelope_context,
};
use xolotl_gateway_websocket::{
    ExternalWebSocketConfig, HARD_FIRST_FRAME_TIMEOUT_MS, HARD_IDLE_TIMEOUT_MS,
    HARD_MAX_CONNECTIONS, HARD_MAX_FRAME_BYTES,
};
use xolotl_types::external::{Role, SessionContext};

#[test]
fn external_websocket_config_is_bounded() -> Result<()> {
    let config = ExternalWebSocketConfig {
        max_frame_bytes: usize::MAX,
        first_frame_timeout_ms: u64::MAX,
        idle_timeout_ms: u64::MAX,
        max_connections: usize::MAX,
        ..ExternalWebSocketConfig::default()
    }
    .bounded();
    ensure!(
        config.max_frame_bytes == HARD_MAX_FRAME_BYTES,
        "max_frame_bytes: {}",
        config.max_frame_bytes
    );
    ensure!(
        config.first_frame_timeout_ms == HARD_FIRST_FRAME_TIMEOUT_MS,
        "first_frame_timeout_ms: {}",
        config.first_frame_timeout_ms
    );
    ensure!(
        config.idle_timeout_ms == HARD_IDLE_TIMEOUT_MS,
        "idle_timeout_ms: {}",
        config.idle_timeout_ms
    );
    ensure!(
        config.max_connections == HARD_MAX_CONNECTIONS,
        "max_connections: {}",
        config.max_connections
    );
    Ok(())
}

#[test]
fn secure_envelope_context_must_match_session() -> Result<()> {
    let context = SessionContext {
        installation_id: "install".into(),
        projection_id: "source".into(),
        role: Role::Source,
        registry_hash: "hash".into(),
        credential_generation: 2,
        binding_generation: 3,
        installation_config_version: 4,
        projection_version: 5,
        presentation_config_generation: 6,
        alias_catalog_generation: 7,
        session_id: "session".into(),
    };
    let credential = ExternalCredential::new("install", 2, [0x52; 32]);
    let envelope = credential
        .seal_with_aad(
            b"frame",
            EnvelopeAad {
                projection_id: "source".into(),
                role: "source".into(),
                session_id: "session".into(),
                frame_type: "inbound_event".into(),
                binding_generation: 3,
                credential_generation: 2,
                transcript_hash: vec![0; 32],
                ..EnvelopeAad::default()
            },
        )
        .map_err(|error| anyhow::anyhow!("seal envelope: {error:?}"))?;
    validate_secure_external_envelope_context(&envelope, &context)
        .map_err(|error| anyhow::anyhow!("validate envelope context: {error:?}"))?;
    Ok(())
}
