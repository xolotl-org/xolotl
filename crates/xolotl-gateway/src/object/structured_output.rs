//! Explicit object delivery preserves execution outcomes and borrowed credits.

use parking_lot::RwLock;
use std::sync::Arc;
use xolotl_types::{CompletionOrigin, Outcome, TaintSet, TaintedValue, Value};
use xolotl_value_codec::validation::KeyStore;
use xolotl_value_object::EncodedValueRef;

use super::{GatewayObjectReadGrant, IssueObjectReadGrantRequest};
use crate::{
    GatewayAccepted, GatewayError, GatewayOutputEvent, GatewayRuntime, GatewayRuntimeState,
    GatewaySession, now_millis, validate_current_session,
};

mod adapter;
pub use adapter::GatewayOutputExternalizer;
mod encode;
mod policy;
pub use policy::{GatewayOutputDisclosurePolicy, GatewayOutputDisclosureRequest};

/// Original semantic role of one delivered object. Encoding never changes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayOutputKind {
    /// One incremental item before the request's completion.
    Chunk,
    /// A successful final value.
    Done,
    /// A short-circuiting final value.
    Short,
    /// A complete, typed final failure.
    Fail,
}

/// Host policy for one object operation, separate from its borrowed I/O window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayOutputObjectOptions {
    /// Optional maximum simultaneously open value/metadata records.
    /// No record budget or cumulative byte limit is inferred by default.
    pub max_frames: Option<usize>,
    /// Requested grant lifetime, bounded by the active Gateway profile.
    /// `None` uses that profile's normal grant lifetime.
    pub expires_in_ms: Option<u64>,
}

/// Delivery failed without changing the persisted execution outcome.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct GatewayOutputExternalizationError {
    /// Encoding, storage, or disclosure failure. External transports should use
    /// its redacted public message rather than raw storage diagnostics.
    pub error: GatewayError,
    /// Input, commit, and subsequently inspected canonical object sources.
    pub taint: TaintSet,
}

/// One committed and explicitly delegated result retaining its original owner.
///
/// The original chunk's kernel credits and request capacity remain held through
/// encoding, grant issuance, and borrowed transport conversion. Drop this owner
/// only after handing the bounded encoded response to its transport owner, or
/// abandoning delivery. It does not retain or replay previous stream items.
///
/// Chunk, Done and Short objects encode their original Value. Fail objects encode
/// the lossless, externally tagged Failure layout used by shared Serde. The
/// encoding descriptor identifies the value envelope; [`Self::kind`] identifies
/// the payload's role. Referenced nested objects receive no read authority.
#[must_use = "retain this owner until output delivery is acknowledged or abandoned"]
pub struct GatewayExternalizedOutput {
    event: GatewayOutputEvent,
    reference: EncodedValueRef,
    grant: GatewayObjectReadGrant,
    session: GatewaySession,
    runtime_state: Arc<RwLock<GatewayRuntimeState>>,
}

impl GatewayExternalizedOutput {
    /// Original typed result, including the chunk's unreleased capacity.
    pub fn original_event(&self) -> &GatewayOutputEvent {
        &self.event
    }

    /// Original chunk/final-result distinction.
    pub fn kind(&self) -> GatewayOutputKind {
        kind(&self.event)
    }

    /// Completion origin is present only for final outcomes.
    pub fn origin(&self) -> Option<CompletionOrigin> {
        match &self.event {
            GatewayOutputEvent::Chunk(_) => None,
            GatewayOutputEvent::Complete(completion) => Some(completion.origin),
        }
    }

    /// Complete committed payload with an explicit interpretation.
    pub fn reference(&self) -> &EncodedValueRef {
        &self.reference
    }

    /// Host-issued, audience-bound read grant for only this container object.
    pub fn grant(&self) -> &GatewayObjectReadGrant {
        &self.grant
    }

    /// Final canonical publication and disclosure sources, without historical
    /// sources from separately delivered stream items.
    pub fn taint(&self) -> &TaintSet {
        &self.grant.metadata().taint
    }

    /// Recheck live session, expiry, and chunk cancellation before delivery.
    /// Opening the object still checks the retained grant in State.
    pub fn validate(&self) -> Result<(), GatewayError> {
        validate_current_session(&self.runtime_state.read().profile, &self.session)?;
        if self.grant.expires_at_ms() <= now_millis() {
            return Err(GatewayError::Rejected("output read grant expired".into()));
        }
        validate_event(&self.event)
    }
}

impl GatewayRuntime {
    /// Encode and delegate exactly one output through explicit host policy.
    ///
    /// This trusted host API is absent from the transport-facing Gateway trait.
    /// The supplied policy decides disclosure only after durable commit and a
    /// canonical metadata read, including sources from deduplicated content.
    /// Client encoding preferences, outcome provenance, and references do not
    /// authorize disclosure. No nested reference is traversed or granted.
    ///
    /// `scratch` is one nonempty borrowed I/O window; `keys` is an independently
    /// chosen workspace. Neither introduces a cumulative object-size ceiling.
    /// Dropping a polled future drops its original item and upload staging. An
    /// uncertain publication or undelivered grant is never deleted as rollback.
    #[expect(
        clippy::too_many_arguments,
        reason = "audience, output ownership, borrowed workspace and host policy are independent contracts"
    )]
    pub async fn externalize_output_event<K, P>(
        &self,
        session: &GatewaySession,
        accepted: &GatewayAccepted,
        event: GatewayOutputEvent,
        scratch: &mut [u8],
        keys: K,
        options: GatewayOutputObjectOptions,
        disclosure: &P,
    ) -> Result<GatewayExternalizedOutput, GatewayOutputExternalizationError>
    where
        K: KeyStore,
        K::Error: core::fmt::Display,
        P: GatewayOutputDisclosurePolicy + ?Sized,
    {
        self.validate_output_context(session, accepted, &event)
            .map_err(|error| GatewayOutputExternalizationError {
                error,
                taint: sources(&event).clone(),
            })?;

        let committed =
            encode::event(&self.objects, scratch, keys, options.max_frames, &event).await?;
        validate_event(&event).map_err(|error| GatewayOutputExternalizationError {
            error,
            taint: committed.taint.clone(),
        })?;
        let authorization = policy::Authorization {
            session,
            accepted,
            event: &event,
            disclosure,
        };
        let grant = self
            .issue_object_read_grant_authorized(
                session,
                IssueObjectReadGrantRequest {
                    surface_id: accepted.surface_id.clone(),
                    object: TaintedValue::new(
                        Value::blob(committed.reference.blob.clone()),
                        committed.taint,
                    ),
                    offset: 0,
                    length: None,
                    expires_in_ms: options.expires_in_ms,
                },
                &authorization,
            )
            .await
            .map_err(|failure| GatewayOutputExternalizationError {
                error: failure.error,
                taint: failure.taint,
            })?;
        let output = GatewayExternalizedOutput {
            event,
            reference: committed.reference,
            grant,
            session: session.clone(),
            runtime_state: self.state.clone(),
        };
        output
            .validate()
            .map_err(|error| GatewayOutputExternalizationError {
                error,
                taint: output.taint().clone(),
            })?;
        Ok(output)
    }

    pub(super) fn validate_output_context(
        &self,
        session: &GatewaySession,
        accepted: &GatewayAccepted,
        event: &GatewayOutputEvent,
    ) -> Result<(), GatewayError> {
        super::read_grant::record::ReadGrantScope::new(
            &self.profile_snapshot(),
            session,
            &accepted.surface_id,
        )?;
        match event {
            GatewayOutputEvent::Chunk(chunk) => chunk.validate_acceptance(accepted),
            GatewayOutputEvent::Complete(completion) if completion.accepted != *accepted => {
                Err(GatewayError::Rejected(
                    "output acceptance metadata does not match its completion".into(),
                ))
            }
            GatewayOutputEvent::Complete(_) => Ok(()),
        }
    }
}

fn kind(event: &GatewayOutputEvent) -> GatewayOutputKind {
    match event {
        GatewayOutputEvent::Chunk(_) => GatewayOutputKind::Chunk,
        GatewayOutputEvent::Complete(completion) => match completion.output.outcome {
            Outcome::Done(_) => GatewayOutputKind::Done,
            Outcome::Short(_) => GatewayOutputKind::Short,
            Outcome::Fail(_) => GatewayOutputKind::Fail,
        },
    }
}

fn sources(event: &GatewayOutputEvent) -> &TaintSet {
    match event {
        GatewayOutputEvent::Chunk(chunk) => &chunk.taint,
        GatewayOutputEvent::Complete(completion) => &completion.output.taint,
    }
}

fn validate_event(event: &GatewayOutputEvent) -> Result<(), GatewayError> {
    match event {
        GatewayOutputEvent::Chunk(chunk) => chunk.validate_delivery(),
        GatewayOutputEvent::Complete(_) => Ok(()),
    }
}
