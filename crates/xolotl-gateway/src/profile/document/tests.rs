use super::*;
use anyhow::{Context, Result, ensure};
use serde_json::json;

fn document() -> Result<GatewayProfileDocument> {
    serde_json::from_value(json!({
        "profile_name": "app",
        "version": 3,
        "credentials": [{
            "credential_id": "app-key",
            "principal_id": "client",
            "verifier": {"kind": "bearer", "token_hash": "11".repeat(32)}
        }],
        "identity_mappings": [{"principal_id": "client", "identity_path": "process://app"}],
        "surfaces": [{"surface_id": "inspect", "target": "effect://blob/stat"}],
        "principal_surface_bindings": [{
            "principal_id": "client",
            "visible_surfaces": ["inspect"],
            "submit_surfaces": ["inspect"],
            "capability_ceiling": ["perform://effect/blob/stat"]
        }],
        "registered_hosts": ["localhost:9445"],
        "limits": {"max_in_flight_requests": 2, "budget": {"max_inflight_ops": 4}}
    }))
    .context("decode profile")
}

#[test]
fn profile_document_admission_uses_explicit_bindings_and_config_revision() -> Result<()> {
    let document = document()?;
    document.validate_admission("app")?;
    ensure!(!format!("{document:?}").contains(&"11".repeat(32)));
    let profile = document.into_profile()?;
    ensure!(profile.revision == 3);
    ensure!(profile.limits.max_in_flight_requests == 2);
    ensure!(profile.limits.budget.max_inflight_ops == Some(4));
    ensure!(profile.limits.max_stream_items == GatewayLimitProfile::default().max_stream_items);
    ensure!(profile.credentials.len() == 1);
    ensure!(profile.principal_surface_bindings[0].submit_surfaces == ["inspect"]);
    Ok(())
}

#[test]
fn profile_document_rejects_mismatched_names_unknown_fields_and_missing_ceilings() -> Result<()> {
    let document = document()?;
    ensure!(document.validate_admission("other").is_err());
    let mut value = serde_json::to_value(&document)?;
    value["credentials"][0]["token"] = json!("plaintext-must-not-be-accepted");
    ensure!(serde_json::from_value::<GatewayProfileDocument>(value).is_err());
    let mut value = serde_json::to_value(&document)?;
    value["principal_surface_bindings"][0]["capability_ceiling"] = json!([]);
    let unbound: GatewayProfileDocument = serde_json::from_value(value)?;
    ensure!(unbound.validate_admission("app").is_err());
    Ok(())
}

#[test]
fn profile_document_rejects_invalid_credential_generation_and_schema() -> Result<()> {
    let mut value = serde_json::to_value(document()?)?;
    value["credentials"][0]["generation"] = json!(0);
    let document: GatewayProfileDocument = serde_json::from_value(value.clone())?;
    ensure!(document.validate_admission("app").is_err());
    value["credentials"][0]["generation"] = json!(1);
    value["surfaces"][0]["input_schema"] = json!({"type": "unknown-type"});
    let document: GatewayProfileDocument = serde_json::from_value(value)?;
    ensure!(document.validate_admission("app").is_err());
    Ok(())
}

#[test]
fn empty_profile_document_remains_closed() -> Result<()> {
    let document: GatewayProfileDocument =
        serde_json::from_value(json!({"profile_name": "closed", "version": 1}))?;
    document.validate_admission("closed")?;
    let profile = document.into_profile()?;
    ensure!(profile.credentials.is_empty());
    ensure!(profile.surfaces.is_empty());
    ensure!(profile.principal_surface_bindings.is_empty());
    Ok(())
}

#[test]
fn profile_document_output_stream_schema_is_optional_and_independent() -> Result<()> {
    let document = document()?;
    ensure!(
        document.clone().into_profile()?.surfaces[0]
            .output_stream_schema
            .is_none()
    );
    let mut value = serde_json::to_value(document)?;
    value["surfaces"][0]["output_schema"] = json!({"type": "object"});
    value["surfaces"][0]["output_stream_schema"] = json!({"type": "string"});
    let document: GatewayProfileDocument = serde_json::from_value(value)?;
    document.validate_admission("app")?;
    let encoded = serde_json::to_value(&document)?;
    ensure!(encoded["surfaces"][0]["output_schema"] == json!({"type": "object"}));
    ensure!(encoded["surfaces"][0]["output_stream_schema"] == json!({"type": "string"}));
    let profile = document.into_profile()?;
    ensure!(profile.surfaces[0].output_schema.is_some());
    ensure!(profile.surfaces[0].output_stream_schema.is_some());
    Ok(())
}

#[test]
fn profile_document_rejects_invalid_or_misspelled_output_stream_schema() -> Result<()> {
    let mut value = serde_json::to_value(document()?)?;
    value["surfaces"][0]["output_stream_schema"] = json!({"type": "unknown-type"});
    let document: GatewayProfileDocument = serde_json::from_value(value.clone())?;
    ensure!(document.validate_admission("app").is_err());
    value["surfaces"][0]["output_stream_schema"] = json!({"type": "string"});
    value["surfaces"][0]["output_stream_shema"] = json!({"type": "string"});
    ensure!(serde_json::from_value::<GatewayProfileDocument>(value).is_err());
    Ok(())
}
