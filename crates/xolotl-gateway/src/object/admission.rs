//! Object authorization and deferred single-use consumption at execution admission.

use std::collections::BTreeMap;
use xolotl_state::object::ObjectMetadata;
use xolotl_types::{TaintSet, Value};

use super::ticket::{StoredTicket, provenance_ticket_id, validate_committed_receipt};
use super::{GatewayPayloadProvenance, collect_large_value_refs, object_store_error};
use crate::{
    CompiledSurfaceDescriptor, GatewayError, GatewayRuntime, GatewaySession, now_millis,
    validate_content_hash, validate_current_session,
};

#[derive(Default)]
pub(crate) struct ObjectAdmission {
    taint: TaintSet,
    receipt: Option<StoredTicket>,
}

impl ObjectAdmission {
    pub(crate) async fn commit(
        self,
        runtime: &GatewayRuntime,
        session: &GatewaySession,
    ) -> Result<TaintSet, GatewayError> {
        validate_current_session(&runtime.profile_snapshot(), session)?;
        if let Some(mut stored) = self.receipt {
            if stored.ticket.expires_at_ms <= now_millis() {
                return Err(GatewayError::Rejected("upload ticket expired".into()));
            }
            if stored.ticket.single_use {
                stored.ticket.used = true;
                stored.save(&runtime.boot.kernel.state).await?;
            }
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
        let refs = collect_large_value_refs(value);
        if refs.is_empty() {
            return Ok(ObjectAdmission::default());
        }
        let ticket_id = provenance_ticket_id(provenance)?;
        let stored = StoredTicket::load(&self.boot.kernel.state, ticket_id).await?;
        validate_committed_receipt(
            ticket_id,
            &stored.ticket,
            value,
            session,
            surface,
            submission_token,
        )?;
        // Authorization precedes shared-object lookups; each full reference must match.
        let mut checked: BTreeMap<&str, ObjectMetadata> = BTreeMap::new();
        let mut taint = TaintSet::pristine();
        for blob in refs {
            validate_content_hash(&blob.hash)?;
            if !checked.contains_key(blob.hash.as_str()) {
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
                taint.union(&metadata.taint);
                checked.insert(blob.hash.as_str(), metadata);
            }
            if checked
                .get(blob.hash.as_str())
                .is_none_or(|metadata| metadata.blob != *blob)
            {
                return Err(GatewayError::Rejected(
                    "large object reference does not match canonical object metadata".into(),
                ));
            }
        }
        Ok(ObjectAdmission {
            taint,
            receipt: Some(stored),
        })
    }
}
