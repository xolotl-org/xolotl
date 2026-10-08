use super::*;
use crate::policy::{
    CheckCtx, CompiledCheck, OpenContext, PolicyCompileError, PolicyDecision, PolicySnapshot,
    PolicySource,
};
use anyhow::{Context, ensure};
use std::sync::{
    Weak,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_types::{ConstraintSet, Expiry, IdentityRef, RightFlags};

struct ReleaseProbe {
    registry: Weak<RwLock<RegistryInner>>,
    handles: Option<crate::WeakHandleTable>,
    released: Arc<AtomicUsize>,
    unlocked: Arc<AtomicUsize>,
}

impl Drop for ReleaseProbe {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
        if let Some(registry) = self.registry.upgrade()
            && registry.try_write().is_some()
            && self.handles.as_ref().is_none_or(|handles| {
                handles
                    .upgrade()
                    .is_some_and(|handles| handles.try_write().is_some())
            })
        {
            self.unlocked.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[async_trait::async_trait]
impl CompiledCheck for ReleaseProbe {
    async fn evaluate(&self, _: &CheckCtx) -> PolicyDecision {
        PolicyDecision::Allow
    }
    fn name(&self) -> &'static str {
        "release-probe"
    }
}

#[test]
fn retired_native_policies_are_destroyed_after_releasing_the_registry_lock() -> anyhow::Result<()> {
    for action in ["evict", "replace", "invalidate", "disabled", "stale"] {
        let registry = Registry::with_open_cache_capacity(usize::from(action != "disabled"));
        let released = Arc::new(AtomicUsize::new(0));
        let unlocked = Arc::new(AtomicUsize::new(0));
        let make_plan = || CompiledOpenPlan {
            resource: ResourceId::new(1),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: DriverPlan::new(DriverId::new(1), None, 1),
            fast_path: FastPath::Conditional(PolicySnapshot::new(vec![Arc::new(ReleaseProbe {
                registry: Arc::downgrade(&registry.inner),
                handles: None,
                released: released.clone(),
                unlocked: unlocked.clone(),
            })])),
        };
        let grant = Grant {
            id: GrantId::new(1),
            holder: ProcessId::new(7),
            selector: xolotl_types::ResourceSelector::all(),
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::all(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        };
        let mut key = OpenCacheKey::new(
            grant.id,
            ResourceId::new(1),
            Path::parse("effect://cached")?,
            "perform",
            Rights::new(MethodBitmap::ALL, RightFlags::all()),
            IdentityRef::ROOT,
        );
        let revision = registry.revision();
        if action == "stale" {
            registry.register_grant(grant.clone());
        }
        ensure!(
            registry.publish_open_plan(Some(key.clone()), &make_plan(), revision)
                == (action != "stale")
        );
        if matches!(action, "evict" | "replace") {
            if action == "evict" {
                key.resource_path = Path::parse("effect://cached/other")?;
            }
            ensure!(registry.publish_open_plan(Some(key), &make_plan(), revision));
        } else if action == "invalidate" {
            registry.register_grant(grant.clone());
        }
        ensure!(released.load(Ordering::SeqCst) == 1, "{action}");
        ensure!(unlocked.load(Ordering::SeqCst) == 1, "{action}");
        registry.register_grant(grant);
        ensure!(
            unlocked.load(Ordering::SeqCst) == released.load(Ordering::SeqCst),
            "{action}"
        );
        ensure!(registry.open_cache_stats().2 == 0);
    }
    Ok(())
}

struct ReleasePolicy {
    registry: Weak<RwLock<RegistryInner>>,
    handles: crate::WeakHandleTable,
    released: Arc<AtomicUsize>,
    unlocked: Arc<AtomicUsize>,
}

impl PolicySource for ReleasePolicy {
    fn applies_to(&self, _: &OpenContext) -> bool {
        true
    }

    fn compile(&self, _: &OpenContext) -> Result<PolicySnapshot, PolicyCompileError> {
        Ok(PolicySnapshot::new(vec![Arc::new(ReleaseProbe {
            registry: self.registry.clone(),
            handles: Some(self.handles.clone()),
            released: self.released.clone(),
            unlocked: self.unlocked.clone(),
        })]))
    }
}

#[test]
fn installation_failure_keeps_native_captures_until_the_host_releases_its_locks()
-> anyhow::Result<()> {
    for cancelled in [false, true] {
        let kernel = crate::KernelBuilder::in_memory()
            .with_open_cache_capacity(0)
            .build();
        let boot = crate::Bootstrap::from_kernel(kernel);
        let target = boot.register_effect(
            "effect://prepared/drop",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                xolotl_types::Purity::Pure,
                xolotl_types::OutputModeSet::UNARY,
            )],
            Arc::new(crate::driver::EchoDriver),
        )?;
        let registry = boot.kernel().registry();
        let released = Arc::new(AtomicUsize::new(0));
        let unlocked = Arc::new(AtomicUsize::new(0));
        registry.register_policy(Arc::new(ReleasePolicy {
            registry: Arc::downgrade(&registry.inner),
            handles: boot.kernel().handles().downgrade(),
            released: released.clone(),
            unlocked: unlocked.clone(),
        }));
        let prepared = crate::prepare_open(
            registry,
            crate::OpenRequest {
                process: boot.root(),
                resource: registry.resolve_resource(&target)?,
                verb: "perform".into(),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                acting: IdentityRef::ROOT,
                requested_path: Some(target.path().clone()),
                now_millis: 10,
            },
            &[],
        )?;
        if cancelled {
            boot.cancel_process(boot.root())?;
            ensure!(matches!(
                prepared.install_for(
                    &mut boot.kernel().handles().write(),
                    boot.kernel().processes()
                ),
                Err(crate::OpenError::ProcessUnavailable(_))
            ));
        } else {
            let grant = registry
                .grants_of(boot.root())
                .into_iter()
                .next()
                .context("root grant")?;
            registry.register_grant(grant);
            ensure!(matches!(
                prepared.install(boot.kernel().handles()),
                Err(crate::OpenError::RegistryChanged)
            ));
        }
        ensure!(boot.kernel().handles().read().is_empty());
        ensure!(released.load(Ordering::SeqCst) == 0);
        drop(prepared);
        ensure!(released.load(Ordering::SeqCst) == 1);
        ensure!(unlocked.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}
