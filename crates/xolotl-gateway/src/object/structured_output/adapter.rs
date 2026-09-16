//! One host-owned asynchronous adapter, with no queues or detached work.

use std::{future::Future, num::NonZeroUsize, sync::Arc};
use xolotl_value_codec::validation::KeyStore;

use super::{
    GatewayExternalizedOutput, GatewayOutputDisclosurePolicy, GatewayOutputExternalizationError,
    GatewayOutputObjectOptions, sources,
};
use crate::{GatewayAccepted, GatewayError, GatewayOutputEvent, GatewayRuntime, GatewaySession};

/// An explicitly installed host adapter for object delivery at transport edges.
///
/// The returned future owns the event, context, adapter and any factory work.
/// A transport can retain it as one `Send + 'static` pending item without a task
/// or input queue. Dropping it releases the current chunk and unfinished work.
/// No method is added to the transport-facing [`crate::Gateway`] capability.
#[async_trait::async_trait]
pub trait GatewayOutputExternalizer: Send + Sync + 'static {
    /// Commit and explicitly delegate one owned output item.
    async fn externalize(
        self: Arc<Self>,
        session: GatewaySession,
        accepted: GatewayAccepted,
        event: GatewayOutputEvent,
    ) -> Result<GatewayExternalizedOutput, GatewayOutputExternalizationError>;
}

struct Externalizer<F, P> {
    runtime: Arc<GatewayRuntime>,
    scratch_bytes: NonZeroUsize,
    options: GatewayOutputObjectOptions,
    make_keys: F,
    disclosure: P,
}

impl GatewayRuntime {
    /// Bind explicit workspace and disclosure choices for a transport adapter.
    ///
    /// The factory runs only when an event is actually externalized. Its error
    /// retains that event's provenance, without adding credential information.
    /// After the workspace opens, one configured scratch window is allocated.
    /// Successful completion releases both before handing the item to transport.
    /// The factory must own cleanup of cancelled initialization; an opened key
    /// workspace follows [`KeyStore`]'s cleanup contract.
    ///
    /// Send bounds apply only at this host erasure boundary. Statically composed
    /// callers can use [`Self::externalize_output_event`] with local workspaces.
    pub fn output_externalizer<K, Open, E, F, P>(
        self: Arc<Self>,
        scratch_bytes: NonZeroUsize,
        options: GatewayOutputObjectOptions,
        make_keys: F,
        disclosure: P,
    ) -> Arc<dyn GatewayOutputExternalizer>
    where
        K: KeyStore + Send + 'static,
        K::Error: core::fmt::Display + Send,
        for<'a> K::Create<'a>: Send,
        for<'a> K::ComparePrefix<'a>: Send,
        for<'a> K::Append<'a>: Send,
        for<'a> K::Release<'a>: Send,
        Open: Future<Output = Result<K, E>> + Send,
        E: core::fmt::Display + Send,
        F: Fn() -> Open + Send + Sync + 'static,
        P: GatewayOutputDisclosurePolicy + 'static,
    {
        Arc::new(Externalizer {
            runtime: self,
            scratch_bytes,
            options,
            make_keys,
            disclosure,
        })
    }
}

#[async_trait::async_trait]
impl<K, Open, E, F, P> GatewayOutputExternalizer for Externalizer<F, P>
where
    K: KeyStore + Send + 'static,
    K::Error: core::fmt::Display + Send,
    for<'a> K::Create<'a>: Send,
    for<'a> K::ComparePrefix<'a>: Send,
    for<'a> K::Append<'a>: Send,
    for<'a> K::Release<'a>: Send,
    Open: Future<Output = Result<K, E>> + Send,
    E: core::fmt::Display + Send,
    F: Fn() -> Open + Send + Sync + 'static,
    P: GatewayOutputDisclosurePolicy + 'static,
{
    async fn externalize(
        self: Arc<Self>,
        session: GatewaySession,
        accepted: GatewayAccepted,
        event: GatewayOutputEvent,
    ) -> Result<GatewayExternalizedOutput, GatewayOutputExternalizationError> {
        let taint = sources(&event).clone();
        self.runtime
            .validate_output_context(&session, &accepted, &event)
            .map_err(|error| GatewayOutputExternalizationError {
                error,
                taint: taint.clone(),
            })?;
        let keys = (self.make_keys)()
            .await
            .map_err(|error| GatewayOutputExternalizationError {
                error: GatewayError::Rejected(format!(
                    "output key workspace could not open: {error}"
                )),
                taint: taint.clone(),
            })?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(self.scratch_bytes.get())
            .map_err(|error| GatewayOutputExternalizationError {
                error: GatewayError::Rejected(format!(
                    "output I/O window could not be allocated: {error}"
                )),
                taint,
            })?;
        scratch.resize(self.scratch_bytes.get(), 0);
        self.runtime
            .externalize_output_event(
                &session,
                &accepted,
                event,
                &mut scratch,
                keys,
                self.options,
                &self.disclosure,
            )
            .await
    }
}
