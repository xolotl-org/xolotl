use std::{
    future::{Ready, ready},
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{Result, ensure};
use xolotl_federation::{
    Digest, FederationError, FederationNodeId, FederationObjectReceiveStore,
    FederationObjectReferenceGuard, FederationObjectReferenceStore, FederationSubject,
    MemoryFederationStore, ObjectGrantId, ObjectReceivePhase, ObjectReceiveSpec, ObjectReceiveView,
    bind_verified_object,
};
use xolotl_types::BlobRef;

struct TestGuard(BlobRef);

impl FederationObjectReferenceGuard for TestGuard {
    fn committed_blob(&self) -> &BlobRef {
        &self.0
    }
}

struct ReferencePort {
    committed: BlobRef,
    calls: AtomicUsize,
}

impl FederationObjectReferenceStore for ReferencePort {
    type Guard<'a> = TestGuard;
    type Publish<'a> = Ready<Result<Self::Guard<'a>, FederationError>>;

    fn publish_and_hold<'a>(&'a self, _view: &'a ObjectReceiveView) -> Self::Publish<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        ready(Ok(TestGuard(self.committed.clone())))
    }
}

#[tokio::test]
async fn binding_rejects_pending_or_wrong_application_descriptor() -> Result<()> {
    let local = FederationNodeId::from_bytes([1; 48]);
    let store = MemoryFederationStore::new(local);
    let blob = BlobRef {
        hash: BlobRef::sha384_hex(&[4; 48]),
        size: 16,
        mime: Some("text/plain".into()),
    };
    let spec = ObjectReceiveSpec {
        provider: FederationNodeId::from_bytes([2; 48]),
        subject: FederationSubject::Node(local),
        grant: ObjectGrantId::new(1)?,
        grant_revision: 1,
        blob: blob.clone(),
        owner: Digest::from_bytes([3; 48]),
    };
    let pending = store.begin_receive(spec)?;
    let wrong = ReferencePort {
        committed: BlobRef {
            size: blob.size + 1,
            ..blob.clone()
        },
        calls: AtomicUsize::new(0),
    };
    ensure!(
        bind_verified_object(&store, &wrong, pending.transfer).await
            == Err(FederationError::Conflict)
    );
    ensure!(wrong.calls.load(Ordering::Relaxed) == 0);

    let verified = store.mark_object_verified(pending.transfer, pending.revision, &blob)?;
    ensure!(
        bind_verified_object(&store, &wrong, verified.transfer).await
            == Err(FederationError::Conflict)
    );
    ensure!(store.object_receive(verified.transfer)? == Some(verified.clone()));
    let correct = ReferencePort {
        committed: blob,
        calls: AtomicUsize::new(0),
    };
    let bound = bind_verified_object(&store, &correct, verified.transfer).await?;
    ensure!(bound.phase == ObjectReceivePhase::Bound);
    ensure!(bind_verified_object(&store, &correct, verified.transfer).await? == bound);
    ensure!(correct.calls.load(Ordering::Relaxed) == 1);
    Ok(())
}
