use super::*;
use crate::{CompiledGatewayProfile, GatewayProfile, GatewaySurface};
use anyhow::{Context, Result, ensure};
use xolotl_types::{Path, ResourceName};

fn schema(kind: &str) -> Value {
    Value::map(BTreeMap::from([(
        "type".into(),
        Value::string(kind.into()),
    )]))
}

fn surface() -> Result<GatewaySurface> {
    Ok(GatewaySurface::effect_invoke(
        "generate",
        ResourceName::new(Path::parse("effect://generate/text")?),
    ))
}

fn compile(surface: GatewaySurface) -> Result<CompiledSurfaceDescriptor> {
    CompiledGatewayProfile::compile(GatewayProfile::new("schema").with_surface(surface))?
        .surface_by_id("generate")
        .cloned()
        .context("compiled surface")
}

#[test]
fn output_stream_schema_is_independent_of_input_and_final_output() -> Result<()> {
    let surface = compile(
        surface()?
            .with_schema(Some(schema("integer")), Some(schema("object")))
            .with_output_stream_schema(schema("string")),
    )?;
    validate_surface_output_stream_item(&surface, &Value::string("delta".into()))?;
    validate_surface_output(&surface, &Value::map(BTreeMap::new()))?;
    validate_surface_input(&surface, &Value::integer(7))?;
    ensure!(validate_surface_output_stream_item(&surface, &Value::integer(7)).is_err());
    ensure!(validate_surface_output_stream_item(&surface, &Value::map(BTreeMap::new())).is_err());
    ensure!(validate_surface_output(&surface, &Value::string("delta".into())).is_err());
    Ok(())
}

#[test]
fn missing_output_stream_schema_does_not_inherit_final_output_schema() -> Result<()> {
    let surface = compile(surface()?.with_schema(None, Some(schema("object"))))?;
    validate_surface_output_stream_item(&surface, &Value::string("delta".into()))?;
    validate_surface_output_stream_item(&surface, &Value::integer(7))?;
    ensure!(validate_surface_output(&surface, &Value::integer(7)).is_err());
    Ok(())
}

#[test]
fn output_stream_array_schema_validates_the_complete_item() -> Result<()> {
    let surface = compile(
        surface()?.with_output_stream_schema(Value::map(BTreeMap::from([
            ("type".into(), Value::string("array".into())),
            ("items".into(), schema("string")),
        ]))),
    )?;
    validate_surface_output_stream_item(
        &surface,
        &Value::list(vec![Value::string("delta".into())]),
    )?;
    ensure!(validate_surface_output_stream_item(&surface, &Value::string("delta".into())).is_err());
    ensure!(
        validate_surface_output_stream_item(&surface, &Value::list(vec![Value::integer(7)]))
            .is_err()
    );
    Ok(())
}
