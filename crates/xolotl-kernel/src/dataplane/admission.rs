//! Resolve only the invocation payload while retaining one authority-table view.

use super::*;
use xolotl_types::{ReplayClass, ResourceId};

pub(super) struct Denial {
    pub resource: Option<ResourceId>,
    pub replay: ReplayClass,
    pub failure: Failure,
}

impl DataPlane {
    pub(super) fn resolve_invocation<'op>(
        &self,
        op: &'op Operation,
        options: InvocationOptions,
        async_child: bool,
    ) -> Result<(Resolved, Invocation<'op>), Denial> {
        let handles = self.handles.read();
        let h = handles.get(op.handle).ok_or_else(|| Denial {
            resource: None,
            replay: ReplayClass::Observation,
            failure: Failure::policy("handle", "stale or unknown handle"),
        })?;
        let entry = h.driver_plan.entry(op.method).ok_or_else(|| Denial {
            resource: Some(h.resource),
            replay: ReplayClass::Observation,
            failure: Failure::policy("method", "method absent from opened dispatch plan"),
        })?;
        let contract = entry.contract;
        let denied = |failure| Denial {
            resource: Some(h.resource),
            replay: contract.replay,
            failure,
        };
        let invocation = Invocation::admit(
            op,
            GrantedMethod {
                owner: h.process,
                acting: h.acting,
                rights: h.rights,
                resource: h.resource,
                contract,
            },
            options,
        )
        .map_err(denied)?;
        // Propagation and ownership precede every host admission callback,
        // including reconciliation of an already accepted child.
        if matches!(op.output, OutputMode::AsyncProcess) && !async_child {
            if !h
                .rights
                .flags
                .contains(xolotl_types::RightFlags::SPAWN_WITH)
            {
                return Err(denied(Failure::PermissionDenied {
                    required: vec!["SPAWN_WITH".into()],
                    actual: vec![],
                }));
            }
            if !self.has_async_process_host() {
                return Err(denied(Failure::policy(
                    "async-process",
                    "AsyncProcess requires a host owner",
                )));
            }
        }
        // Copy only the dispatch payload, excluding the unused open-time verb.
        // Policies, drivers and Fact callbacks run after this guard is released.
        Ok((
            Resolved {
                resource: h.resource,
                plan: h.driver_plan.clone(),
                fast_path: h.fast_path.clone(),
                bound_path: h.bound_path.clone(),
                input_admission: entry.input_admission,
            },
            invocation,
        ))
    }
}
