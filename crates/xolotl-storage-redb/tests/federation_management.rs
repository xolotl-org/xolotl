#![cfg(feature = "federation")]

use anyhow::{Result, ensure};
use xolotl_federation::{
    AuthorityOwner, ExportAccess, ExportName, FederationError, FederationManagement,
    FederationNodeId, PeerAdmission,
};
use xolotl_storage_redb::RedbStore;

const LOCAL: FederationNodeId = FederationNodeId::from_bytes([60; 48]);
const APP: FederationNodeId = FederationNodeId::from_bytes([61; 48]);
const CONFIG: FederationNodeId = FederationNodeId::from_bytes([62; 48]);

fn admission(generation: u64) -> PeerAdmission {
    PeerAdmission {
        minimum_online_generation: generation,
        allowed_authorization_digests: vec![[generation as u8; 48]],
    }
}

#[test]
fn management_authority_is_paged_and_cannot_take_over_manifest_rows() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("federation.redb");
    let store = RedbStore::open(&path)?.federation_store(LOCAL)?;
    let notes = ExportName::new("notes")?;
    let tasks = ExportName::new("tasks")?;
    let serve = ExportAccess {
        serve: true,
        receive: false,
    };

    ensure!(store.set_peer(APP, None, true)? == 1);
    ensure!(store.set_manifest_peer_authority(CONFIG, None, false)? == 1);
    ensure!(store.set_export(APP, notes.clone(), None, serve)? == 1);
    ensure!(store.set_export(APP, tasks.clone(), None, serve)? == 1);
    ensure!(store.set_manifest_export_authority(CONFIG, notes.clone(), None, serve)? == 1);
    ensure!(store.set_online_admission(APP, None, admission(1))? == 1);
    ensure!(store.set_manifest_peer_admission(CONFIG, None, admission(1))? == 1);

    let first = store.scan_peers(None, 1)?;
    ensure!(first.len() == 1 && first[0].peer == APP);
    ensure!(first[0].owner == AuthorityOwner::Application);
    let second = store.scan_peers(Some(APP), 1)?;
    ensure!(second.len() == 1 && second[0].peer == CONFIG);
    ensure!(second[0].owner == AuthorityOwner::Manifest);
    ensure!(store.scan_peers(Some(CONFIG), 1)?.is_empty());
    ensure!(matches!(
        store.scan_peers(None, 0),
        Err(FederationError::Capacity)
    ));
    ensure!(store.scan_exports(APP, None, 1)?[0].export == notes);
    ensure!(store.scan_exports(APP, Some(&notes), 1)?[0].export == tasks);
    ensure!(store.scan_exports(APP, Some(&tasks), 1)?.is_empty());

    ensure!(matches!(
        store.set_peer(APP, None, false),
        Err(FederationError::RevisionConflict)
    ));
    ensure!(matches!(
        store.set_export(APP, notes.clone(), None, serve),
        Err(FederationError::RevisionConflict)
    ));
    ensure!(matches!(
        store.set_online_admission(APP, None, admission(2)),
        Err(FederationError::RevisionConflict)
    ));
    ensure!(matches!(
        store.set_peer(CONFIG, Some(1), true),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_export(CONFIG, notes.clone(), Some(1), serve),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_online_admission(CONFIG, Some(1), admission(2)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_manifest_peer_authority(APP, Some(1), false),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_manifest_export_authority(APP, notes.clone(), Some(1), serve),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_manifest_peer_admission(APP, Some(1), admission(2)),
        Err(FederationError::Conflict)
    ));
    ensure!(store.list_manifest_peer_authorities()? == vec![(CONFIG, 1, false)]);
    ensure!(store.list_manifest_export_authorities(APP)?.is_empty());
    ensure!(store.list_manifest_export_authorities(CONFIG)?.len() == 1);

    drop(store);
    let store = RedbStore::open(&path)?.federation_store(LOCAL)?;
    ensure!(
        store
            .peer(APP)?
            .is_some_and(|row| row.owner == AuthorityOwner::Application)
    );
    ensure!(
        store
            .peer(CONFIG)?
            .is_some_and(|row| row.owner == AuthorityOwner::Manifest)
    );
    ensure!(
        store
            .export(CONFIG, &notes)?
            .is_some_and(|row| row.owner == AuthorityOwner::Manifest)
    );
    ensure!(
        store
            .online_admission(CONFIG)?
            .is_some_and(|row| row.owner == AuthorityOwner::Manifest)
    );
    Ok(())
}
