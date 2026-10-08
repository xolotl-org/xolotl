use anyhow::{Result, ensure};
use xolotl_federation::{
    Digest, FederationError, FederationNodeId, FederationObjectReceiveStore, FederationSubject,
    MemoryFederationStore, ObjectGrantId, ObjectReceiveSpec,
};
use xolotl_types::BlobRef;

#[test]
fn volatile_receive_gc_fence_matches_the_durable_store_contract() -> Result<()> {
    let local = FederationNodeId::from_bytes([81; 48]);
    let store = MemoryFederationStore::new(local);
    let blob = BlobRef {
        hash: BlobRef::sha384_hex(&[91; 48]),
        size: 12,
        mime: None,
    };
    let spec = ObjectReceiveSpec {
        provider: FederationNodeId::from_bytes([82; 48]),
        subject: FederationSubject::Node(local),
        grant: ObjectGrantId::new(1)?,
        grant_revision: 1,
        blob: blob.clone(),
        owner: Digest::from_bytes([83; 48]),
    };
    let pending = store.begin_receive(spec.clone())?;
    ensure!(store.reserve_receive_gc(&blob) == Err(FederationError::Conflict));
    ensure!(
        store.retire_bound_object(pending.transfer, pending.revision)
            == Err(FederationError::Conflict)
    );
    store.retire_unbound_object(pending.transfer, pending.revision)?;

    let fence = store.reserve_receive_gc(&blob)?;
    ensure!(store.active_receive_gc_fences()? == vec![fence.clone()]);
    ensure!(store.begin_receive(spec.clone()) == Err(FederationError::Conflict));
    store.release_receive_gc(&fence)?;
    let newer = store.reserve_receive_gc(&blob)?;
    ensure!(newer.generation > fence.generation);
    ensure!(store.release_receive_gc(&fence) == Err(FederationError::Conflict));
    store.release_receive_gc(&newer)?;
    ensure!(store.begin_receive(spec)?.transfer != pending.transfer);
    Ok(())
}
