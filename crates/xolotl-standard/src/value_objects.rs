//! Explicit structured-value effects, independently selectable from standard-core.

use async_trait::async_trait;
use core::{fmt, future::Future};
use std::{future::Ready, num::NonZeroUsize, sync::Arc};
use xolotl_kernel::{
    Bootstrap, BootstrapError, Driver, DriverContext, DriverError, DriverOutput, DriverUsage,
    MethodSpec, UsageDimension,
};
use xolotl_state::host::object::ObjectStore;
use xolotl_types::{
    Failure, MethodId, Outcome, OutputMode, Purity, ResourceName, TaintedValue, Value,
    value::event::MaterializationLimits,
};
use xolotl_value_codec::validation::{KeyStore, MemoryKeyOptions, MemoryKeyStore};
use xolotl_value_object::{EncodedValueRef, encode_value, read_value};

/// Per-invocation resources for the explicit value/object effects.
///
/// I/O windows never limit cumulative document size. Reading materializes the
/// complete Value in memory only after real EOF and document validation. A
/// provider that needs bounded payload retention should consume
/// [`xolotl_value_object::ValueObjectReader`] events directly instead.
#[derive(Clone, Copy, Debug)]
pub struct ValueObjectConfig {
    /// Size of the borrowed encode or decode window allocated for an active call.
    pub io_bytes: NonZeroUsize,
    /// Optional simultaneous record limit while encoding an already resident value.
    pub write_max_frames: Option<usize>,
    /// Optional resident read admission, including its independent record limit.
    pub read_limits: MaterializationLimits,
}

impl Default for ValueObjectConfig {
    fn default() -> Self {
        Self {
            io_bytes: NonZeroUsize::MIN.saturating_add(16 * 1024 - 1),
            write_max_frames: None,
            read_limits: MaterializationLimits::default(),
        }
    }
}

/// Effects installed from the independently supplied object capabilities.
#[derive(Clone, Debug, Default)]
pub struct InstalledValueObjects {
    /// `effect://value/read`, present only when the supplied store can read.
    pub read: Option<ResourceName>,
    /// `effect://value/write`, present only when the supplied store can upload.
    pub write: Option<ResourceName>,
}

/// Make an allocation-free factory for independently owned resident key stores.
///
/// Data pages allocate only when an invocation actually validates map keys.
/// Their budgets are independent of [`ValueObjectConfig`]. A host may supply
/// any other asynchronous factory to [`install_value_objects`], including a
/// filesystem workspace, without adding that storage adapter to this crate.
pub fn memory_key_factory(
    options: MemoryKeyOptions,
) -> impl Fn() -> Ready<Result<MemoryKeyStore, DriverError>> + Clone {
    move || std::future::ready(Ok(MemoryKeyStore::new(options)))
}

/// Install explicit write/read effects without the standard-core provider set.
///
/// Each available object capability installs one effect with method `invoke`
/// at index zero. The returned paths make a read-only, write-only or empty
/// installation explicit. Installation creates no workspace, worker or buffer.
///
/// `make_keys` creates one exclusively owned workspace per invocation. Its
/// future and store must keep resources guarded through failure/cancellation;
/// see [`KeyStore`]. A synchronous memory factory can use [`memory_key_factory`].
/// A filesystem or custom factory owns its configuration and cleanup separately
/// from the object content store. Only this hosted Driver boundary requires
/// `Send`; the portable codec and object traits keep their local implementations.
///
/// Write accepts any Value, including maps shaped like encoded references, and
/// borrows it through encoding. Read accepts only the exact
/// [`EncodedValueRef`] protocol map, validates canonical metadata and actual EOF,
/// and returns the complete typed Value with all observed provenance. Neither
/// operation opens nested Blob, Tensor or Frame references or grants disclosure.
///
/// The CBOR event profile streams the logical value tree. Repeated resident DAG
/// edges are encoded repeatedly; it does not preserve physical sharing or bound
/// work by the number of shared resident nodes. Once read, ordinary resident
/// Value sharing applies to subsequent pipeline steps.
pub fn install_value_objects<F, Open, K>(
    boot: &Bootstrap,
    objects: ObjectStore,
    config: ValueObjectConfig,
    make_keys: F,
) -> Result<InstalledValueObjects, BootstrapError>
where
    F: Fn() -> Open + Send + Sync + 'static,
    Open: Future<Output = Result<K, DriverError>> + Send,
    K: KeyStore + Send + 'static,
    K::Error: fmt::Display + Send,
    for<'a> K::Create<'a>: Send,
    for<'a> K::ComparePrefix<'a>: Send,
    for<'a> K::Append<'a>: Send,
    for<'a> K::Release<'a>: Send,
{
    let mut installed = InstalledValueObjects::default();
    if !objects.can_read() && !objects.can_write() {
        return Ok(installed);
    }
    let shared = Arc::new(Shared {
        objects,
        config,
        make_keys,
    });
    if shared.objects.can_read() {
        installed.read = Some(
            boot.register_effect(
                "effect://value/read",
                &[
                    MethodSpec::new("invoke", Purity::Pure, MethodSpec::UNARY_ASYNC)
                        .observes_external(),
                ],
                Arc::new(ValueObjectDriver {
                    shared: shared.clone(),
                    action: Action::Read,
                }),
            )?,
        );
    }
    if shared.objects.can_write() {
        installed.write = Some(boot.register_effect(
            "effect://value/write",
            &[MethodSpec::new(
                "invoke",
                Purity::Idempotent,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(ValueObjectDriver {
                shared,
                action: Action::Write,
            }),
        )?);
    }
    Ok(installed)
}

struct Shared<F> {
    objects: ObjectStore,
    config: ValueObjectConfig,
    make_keys: F,
}

#[derive(Clone, Copy)]
enum Action {
    Read,
    Write,
}

struct ValueObjectDriver<F> {
    shared: Arc<Shared<F>>,
    action: Action,
}

#[async_trait]
impl<F, Open, K> Driver for ValueObjectDriver<F>
where
    F: Fn() -> Open + Send + Sync + 'static,
    Open: Future<Output = Result<K, DriverError>> + Send,
    K: KeyStore + Send + 'static,
    K::Error: fmt::Display + Send,
    for<'a> K::Create<'a>: Send,
    for<'a> K::ComparePrefix<'a>: Send,
    for<'a> K::Append<'a>: Send,
    for<'a> K::Release<'a>: Send,
{
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        if !matches!(output, OutputMode::Unary | OutputMode::AsyncProcess) {
            return Err(DriverError::UnsupportedOutput(output));
        }
        let reference = match self.action {
            Action::Read => Some(
                EncodedValueRef::try_from_value(&input)
                    .map_err(|error| DriverError::InvalidInput(error.to_string()))?,
            ),
            Action::Write => None,
        };
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(self.shared.config.io_bytes.get())
            .map_err(|error| {
                DriverError::Other(format!("cannot allocate value I/O window: {error}"))
            })?;
        scratch.resize(self.shared.config.io_bytes.get(), 0);
        let keys = (self.shared.make_keys)().await?;
        if let Some(reference) = reference {
            drop(input);
            return Ok(
                match read_value(
                    &self.shared.objects,
                    &reference,
                    &mut scratch,
                    keys,
                    ctx.taint.clone(),
                    self.shared.config.read_limits,
                )
                .await
                {
                    Ok(value) => DriverOutput::new(Outcome::Done(value.value))
                        .with_taint(value.taint)
                        .with_usage(DriverUsage::from([(
                            UsageDimension::BYTES_READ,
                            reference.blob.size,
                        )])),
                    Err(failure) => source_failure("value_read", failure),
                },
            );
        }
        let value = TaintedValue::new(input, ctx.taint.clone());
        Ok(
            match encode_value(
                &self.shared.objects,
                &mut scratch,
                keys,
                self.shared.config.write_max_frames,
                &value,
            )
            .await
            {
                Ok(committed) => {
                    let bytes = committed.reference.blob.size;
                    DriverOutput::new(Outcome::Done(committed.reference.into_value()))
                        .with_taint(committed.taint)
                        .with_usage(DriverUsage::from([(UsageDimension::BYTES_WRITTEN, bytes)]))
                }
                Err(failure) => source_failure("value_write", failure),
            },
        )
    }
}

fn source_failure<E: fmt::Display>(
    kind: &'static str,
    failure: xolotl_value_object::Failure<E>,
) -> DriverOutput {
    DriverOutput::new(Outcome::Fail(Failure::HandlerError {
        kind: kind.into(),
        message: failure.error.to_string(),
    }))
    .with_taint(failure.taint)
}

#[cfg(test)]
mod tests;
