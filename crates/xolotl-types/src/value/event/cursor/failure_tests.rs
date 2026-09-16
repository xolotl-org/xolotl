use super::*;
use crate::value::event::{MaterializationLimits, ValueBuilder};
use alloc::{format, string::ToString};
use anyhow::{Context, ensure};

fn projected(failure: &Failure, taint: &TaintSet, window: NonZeroUsize) -> anyhow::Result<Value> {
    let mut cursor = ValueCursor::from_failure(failure, taint, window, None)?;
    let mut builder = ValueBuilder::new(MaterializationLimits::default());
    while let Some(event) = cursor.next_event()? {
        if let Event::Data(bytes) = event {
            ensure!(bytes.len() <= window.get());
        }
        builder.push(event)?;
    }
    let value = builder.finish()?;
    ensure!(&value.taint == taint);
    Ok(value.value)
}

#[test]
fn every_failure_variant_has_exactly_its_serde_value_shape() -> anyhow::Result<()> {
    let path = Path::try_new("state")?
        .try_with_cluster("remote")?
        .try_push_literal("vault")?
        .try_push_literal("item")?;
    let cases = [
        Failure::PermissionDenied {
            required: vec!["read".into(), "write".into(), "invoke".into()],
            actual: vec!["read".into(), String::new()],
        },
        Failure::NoHandler { path: path.clone() },
        Failure::BudgetExhausted {
            dim: "bytes\0retained".into(),
        },
        Failure::RateLimited,
        Failure::ApprovalPending {
            approval_key: "approval/42".into(),
            reason: "允许访问？".into(),
        },
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Quarantined {
            op_id: "op-7".into(),
            reason: "unknown completion".into(),
        },
        Failure::InvalidInput {
            reason: "输入无效".into(),
        },
        Failure::HandlerError {
            kind: "provider".into(),
            message: "failed\nrequest".into(),
        },
        Failure::KernelNamespaceProtected,
        Failure::PolicyViolation {
            policy: "sources".into(),
            detail: "protected input".into(),
        },
        Failure::PathInvalid {
            path: path.clone(),
            reason: "unbound resource".into(),
        },
        Failure::Custom {
            kind: "application".into(),
            message: String::new(),
        },
    ];
    let taint = TaintSet::of(TaintSource::Protected { path });
    for failure in cases {
        for window in [
            NonZeroUsize::MIN,
            NonZeroUsize::new(7).context("window")?,
            NonZeroUsize::MAX,
        ] {
            let value = projected(&failure, &taint, window)?;
            ensure!(
                serde_json::to_value(&value)? == serde_json::to_value(&failure)?,
                "different projection for {failure:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_long_reason_borrows_original_bytes_with_only_active_frames() -> anyhow::Result<()> {
    let failure = Failure::InvalidInput {
        reason: "雪🙂".repeat(20_000),
    };
    let Failure::InvalidInput { reason } = &failure else {
        anyhow::bail!("wrong failure fixture");
    };
    let original = reason.as_bytes();
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::from_failure(
        &failure,
        &taint,
        NonZeroUsize::new(2).context("window")?,
        Some(4),
    )?;
    let mut offset = 0;
    let mut first = None;
    while let Some(event) = cursor.next_event()? {
        if let Event::Data(bytes) = event
            && bytes.as_ptr().addr() >= original.as_ptr().addr()
            && bytes.as_ptr().addr() < original.as_ptr().addr() + original.len()
        {
            ensure!(bytes.len() <= 2);
            ensure!(core::ptr::eq(bytes.as_ptr(), original[offset..].as_ptr()));
            ensure!(bytes == &original[offset..offset + bytes.len()]);
            first.get_or_insert(bytes);
            offset += bytes.len();
        }
        ensure!(cursor.frames.len() <= 4 && cursor.frames.capacity() <= 4);
    }
    ensure!(offset == original.len());
    drop(cursor);
    ensure!(first.context("missing borrowed reason")? == &original[..2]);
    Ok(())
}

#[test]
fn permission_lists_do_not_allocate_cursor_storage_for_their_width() -> anyhow::Result<()> {
    let failure = Failure::PermissionDenied {
        required: (0..10_000)
            .map(|index| format!("required/{index}"))
            .collect(),
        actual: (0..10_000).map(|index| format!("actual/{index}")).collect(),
    };
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::from_failure(&failure, &taint, NonZeroUsize::MIN, Some(5))?;
    let mut strings = 0;
    while let Some(event) = cursor.next_event()? {
        if event == Event::Begin(Kind::String) {
            strings += 1;
        }
        ensure!(cursor.frames.len() <= 5 && cursor.frames.capacity() <= 5);
    }
    ensure!(strings == 20_000);
    Ok(())
}

#[test]
fn path_text_uses_the_canonical_formatter_for_every_shape() -> anyhow::Result<()> {
    for path in [
        Path::try_new("state")?,
        Path::try_new("state")?.try_with_cluster("remote")?,
        Path::try_new("state")?.try_push_literal("item")?,
        Path::try_new("state")?
            .try_with_cluster("remote")?
            .try_push_literal("a")?
            .try_push_literal("b")?,
        // A path-invalid diagnostic may carry unchecked path components.
        Path::new("state")
            .with_cluster("remote")
            .push("雪")
            .push("")
            .push("x/y"),
    ] {
        ensure!(path.canonical_parts().collect::<String>() == path.to_string());
        let failure = Failure::NoHandler { path };
        let value = projected(&failure, &TaintSet::pristine(), NonZeroUsize::MIN)?;
        ensure!(serde_json::to_value(value)? == serde_json::to_value(failure)?);
    }
    Ok(())
}
