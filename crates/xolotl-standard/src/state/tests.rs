use super::*;
use anyhow::ensure;
use std::collections::BTreeMap;
use xolotl_types::{IdentityRef, Path, ProcessId};

#[tokio::test]
async fn write_preserves_control_shaped_data_and_compare_set_distinguishes_missing_from_null()
-> anyhow::Result<()> {
    let backend = xolotl_state::InMemoryBackend::new().into_backend();
    let driver = StateDriver::new(backend.clone());
    let path = Path::parse("state://value")?;
    let context =
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_target_path(path.clone());
    let value = Value::map(BTreeMap::from([
        ("cas".into(), Value::boolean(true)),
        ("value".into(), Value::integer(3)),
    ]));
    driver
        .call(MethodId::new(1), value.clone(), OutputMode::Unary, &context)
        .await?;
    ensure!(backend.read(&path).await? == Some(value));
    backend.write_set(&path, Value::null()).await?;
    let replacement = Value::map(BTreeMap::from([("value".into(), Value::integer(5))]));
    ensure!(
        driver
            .call(
                MethodId::new(5),
                replacement.clone(),
                OutputMode::Unary,
                &context
            )
            .await
            .is_err()
    );
    let Some(mut fields) = replacement.into_map() else {
        anyhow::bail!("expected map")
    };
    fields.insert("expected".into(), Value::null())?;
    driver
        .call(
            MethodId::new(5),
            Value::from(fields),
            OutputMode::Unary,
            &context,
        )
        .await?;
    ensure!(backend.read(&path).await? == Some(Value::integer(5)));
    Ok(())
}

#[tokio::test]
async fn state_atomic_failures_deliver_observed_sources_without_disclosing_values()
-> anyhow::Result<()> {
    let backend = xolotl_state::InMemoryBackend::new().into_backend();
    let path = Path::parse("state://private")?;
    let protected = TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
    backend
        .write_set_tainted(
            &path,
            Value::string("atomic-private-content".into()),
            protected.clone(),
        )
        .await?;
    let driver = StateDriver::new(backend);
    let context = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_target_path(path);
    for (method, input) in [
        (
            5,
            Value::map(BTreeMap::from([("value".into(), Value::integer(1))])),
        ),
        (2, Value::integer(1)),
        (
            4,
            Value::map(BTreeMap::from([(
                "max_encoded_bytes".into(),
                Value::integer(1),
            )])),
        ),
    ] {
        let output = driver
            .call(MethodId::new(method), input, OutputMode::Unary, &context)
            .await?;
        ensure!(output.taint == protected);
        let Outcome::Fail(failure) = output.outcome else {
            anyhow::bail!("expected observed failure");
        };
        ensure!(!failure.to_string().contains("atomic-private-content"));
    }
    Ok(())
}
