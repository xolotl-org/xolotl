//! Object authorization and deferred single-use consumption at execution admission.

use std::collections::HashSet;
use xolotl_types::{TaintSet, Value};

use super::ticket::{
    StoredTicket, provenance_ticket_id, validate_committed_members, validate_upload_ticket_scope,
};
use super::{GatewayPayloadProvenance, large_ref_values, object_store_error};
use crate::{
    CompiledSurfaceDescriptor, GatewayError, GatewayRuntime, GatewaySession, validate_content_hash,
    validate_current_session,
};

#[derive(Default)]
pub(crate) struct ObjectAdmission {
    taint: TaintSet,
    receipt: Option<StoredTicket>,
    items: Vec<Value>,
    surface_id: String,
    submission_token: Option<String>,
}

impl ObjectAdmission {
    pub(crate) fn requires_idempotency(&self) -> bool {
        self.receipt
            .as_ref()
            .is_some_and(|stored| stored.ticket.single_use)
    }

    pub(crate) async fn commit(
        self,
        runtime: &GatewayRuntime,
        session: &GatewaySession,
        identity: Option<&str>,
    ) -> Result<TaintSet, GatewayError> {
        let profile = runtime.profile_snapshot();
        validate_current_session(&profile, session)?;
        if let Some(stored) = self.receipt {
            let surface = profile.surface_by_id(&self.surface_id).ok_or_else(|| {
                GatewayError::Rejected("upload ticket surface is no longer available".into())
            })?;
            if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
                return Err(GatewayError::Rejected(
                    "upload ticket surface is not callable by principal".into(),
                ));
            }
            stored
                .consume(
                    super::ticket::TicketContext {
                        state: runtime.boot.kernel().state(),
                        runtime: runtime.boot.kernel().host_runtime(),
                    },
                    identity,
                    &self.items,
                    session,
                    surface,
                    self.submission_token.as_deref(),
                )
                .await?;
        }
        Ok(self.taint)
    }
}

impl GatewayRuntime {
    pub(crate) async fn admit_input_objects(
        &self,
        value: &Value,
        provenance: Option<&GatewayPayloadProvenance>,
        session: &GatewaySession,
        surface: &CompiledSurfaceDescriptor,
        submission_token: Option<&str>,
    ) -> Result<ObjectAdmission, GatewayError> {
        let mut refs = Vec::new();
        let mut unique_items = HashSet::new();
        for item in large_ref_values(value) {
            let blob = item.backing_blob().ok_or_else(|| {
                GatewayError::Rejected("large object reference is invalid".into())
            })?;
            validate_content_hash(&blob.hash)?;
            if unique_items.insert(item) {
                refs.push(item);
            }
        }
        if refs.is_empty() {
            return Ok(ObjectAdmission::default());
        }
        let ticket_id = provenance_ticket_id(provenance)?;
        let stored = StoredTicket::load(self.boot.kernel().state(), ticket_id).await?;
        validate_upload_ticket_scope(
            ticket_id,
            &stored.ticket,
            session,
            surface,
            submission_token,
            self.boot.kernel().host_runtime().now_millis(),
        )?;
        validate_committed_members(&stored.ticket, refs.iter().copied())?;
        // Check every typed member before the first shared object-store lookup.
        let mut checked = HashSet::new();
        let mut taint = TaintSet::pristine();
        for item in &refs {
            let blob = item.backing_blob().ok_or_else(|| {
                GatewayError::Rejected("large object reference is invalid".into())
            })?;
            if !checked.insert(blob) {
                continue;
            }
            let metadata = self
                .objects
                .metadata(blob)
                .await
                .map_err(object_store_error)?
                .ok_or_else(|| {
                    GatewayError::Rejected(
                        "large object reference is not present in the object store".into(),
                    )
                })?;
            if metadata.blob != *blob {
                return Err(GatewayError::Rejected(
                    "large object reference does not match canonical object metadata".into(),
                ));
            }
            taint.union(&metadata.taint);
        }
        Ok(ObjectAdmission {
            taint,
            receipt: Some(stored),
            items: refs.into_iter().cloned().collect(),
            surface_id: surface.surface_id.clone(),
            submission_token: submission_token.map(str::to_string),
        })
    }
}
