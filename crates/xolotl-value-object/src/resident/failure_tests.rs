use super::encode_failure;
use alloc::{string::String, vec};
use anyhow::{Context as _, Result, ensure};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::Ordering,
    task::{Context, Waker},
};
use xolotl_types::{
    Failure, Path, TaintSet, TaintSource,
    value::event::{MaterializationLimits, ValueBuilder},
};
use xolotl_value_codec::cbor::{DecodeStatus, Decoder};

use crate::test_support::{Store, WriteMode, assert_cleaned, keys, run};

fn decoded(bytes: &[u8]) -> Result<xolotl_types::TaintedValue> {
    let mut decoder = Decoder::new(keys(), None);
    let mut builder = ValueBuilder::new(MaterializationLimits::default());
    let mut input = bytes;
    while !input.is_empty() {
        let step = run(decoder.decode(input))?;
        ensure!(step.consumed != 0);
        input = &input[step.consumed..];
        if let DecodeStatus::Event(event) = step.status {
            builder.push(event)?;
        }
    }
    decoder.finish()?;
    Ok(builder.finish()?)
}

#[test]
fn failure_objects_preserve_fields_and_sources_through_short_writes() -> Result<()> {
    let cases = [
        Failure::PermissionDenied {
            required: vec!["read".into(), "write".into(), "invoke".into()],
            actual: vec!["read".into(), String::new()],
        },
        Failure::HandlerError {
            kind: "provider".into(),
            message: "长期运行任务的完整错误详情🙂".repeat(1_000),
        },
        Failure::PathInvalid {
            path: Path::try_new("effect")?
                .try_with_cluster("remote")?
                .try_push_literal("inference")?,
            reason: "unbound target".into(),
        },
        Failure::Timeout,
    ];
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/failure-source")?,
    });
    for failure in cases {
        let store = Store::new(2);
        let mut scratch = [0; 7];
        let committed = run(encode_failure(
            &store,
            &mut scratch,
            keys(),
            None,
            &failure,
            &taint,
        ))?;
        let (bytes, metadata) = {
            let data = store.shared.data();
            (
                data.published
                    .clone()
                    .context("failure bytes were not published")?,
                data.metadata.clone().context("failure metadata missing")?,
            )
        };
        ensure!(metadata.blob == committed.reference.blob);
        ensure!(metadata.taint.contains_all(&taint));
        ensure!(store.shared.commits.load(Ordering::SeqCst) == 1);
        let result = decoded(&bytes)?;
        ensure!(result.taint == taint);
        ensure!(serde_json::to_value(&result.value)? == serde_json::to_value(&failure)?);
    }
    Ok(())
}

#[test]
fn cancelled_failure_encoding_releases_staging_and_keeps_the_borrowed_input() -> Result<()> {
    let failure = Failure::HandlerError {
        kind: "provider".into(),
        message: "message".repeat(10_000),
    };
    let taint = TaintSet::author();
    let store = Store::new(1);
    store.write_mode.set(WriteMode::Pending);
    let mut scratch = [0; 7];
    {
        let mut future = pin!(encode_failure(
            &store,
            &mut scratch,
            keys(),
            None,
            &failure,
            &taint
        ));
        ensure!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert_cleaned(&store)?;
    let Failure::HandlerError { message, .. } = &failure else {
        anyhow::bail!("wrong failure fixture");
    };
    ensure!(message.len() == 70_000);
    Ok(())
}
