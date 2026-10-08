#[path = "support/decision_contract.rs"]
pub mod contract;

use anyhow::Result;
use xolotl_federation::MemoryFederationStore;

#[test]
fn rejected_write_retains_time_without_committing_business_changes() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::rejected_write_retains_time_contract(
        &peers,
        &MemoryFederationStore::new(peers.publisher),
    )
}

#[test]
fn publisher_online_authority_is_checked_at_the_memory_decision() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::publisher_contract(&peers, &MemoryFederationStore::new(peers.publisher))
}

#[test]
fn receiver_install_and_accept_share_current_online_authority() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::receiver_contract(
        &peers,
        &MemoryFederationStore::new(peers.publisher),
        &MemoryFederationStore::new(peers.receiver),
    )
}

#[test]
fn public_admission_rejects_configured_peers_in_the_disclosure_lock() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::public_contract(&peers, &MemoryFederationStore::new(peers.publisher))
}

#[test]
fn staged_object_disclosure_checks_revocation_and_fresh_time() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::object_contract(&peers, &MemoryFederationStore::new(peers.publisher))
}

#[test]
fn queued_hosted_request_uses_decision_time_for_the_subject_grant() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::hosted_contract(&peers, &MemoryFederationStore::new(peers.publisher))
}

#[test]
fn object_receiver_verification_is_a_new_online_admission_decision() -> Result<()> {
    let peers = contract::Peers::new()?;
    contract::object_receiver_contract(&peers, &MemoryFederationStore::new(peers.receiver))
}

#[test]
fn read_only_memory_delivery_keeps_the_shared_floor_and_checks_fresh_authority() -> Result<()> {
    use anyhow::ensure;
    use std::sync::atomic::Ordering;
    use xolotl_federation::{
        FederationAdmission, FederationError, FederationStore, FederationSubject,
        InspectSubscriptionRequest,
    };
    let peers = contract::Peers::new()?;
    let store = MemoryFederationStore::new(peers.publisher);
    contract::publisher_setup(&peers, &store)?;
    store.open(peers.open())?;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    let request = InspectSubscriptionRequest {
        authenticated_subscriber: peers.receiver,
        subscription: peers.subscription(),
    };
    let subject = FederationSubject::Node(peers.receiver);
    remote.inspect_subscription(request)?;
    peers.time.store(170, Ordering::SeqCst);
    remote.authorize_subscription_delivery(&subject, request, true, 0)?;
    store.authorize_subscription_delivery(&subject, request, true, 150)?;
    ensure!(matches!(
        store.authorize_subscription_delivery(&subject, request, true, 149),
        Err(FederationError::ClockRollback)
    ));
    peers.time.store(149, Ordering::SeqCst);
    ensure!(matches!(
        remote.authorize_subscription_delivery(&subject, request, true, 0),
        Err(FederationError::ClockRollback)
    ));
    peers.time.store(170, Ordering::SeqCst);
    store.set_peer_authority(peers.receiver, Some(1), false)?;
    ensure!(matches!(
        remote.authorize_subscription_delivery(&subject, request, true, 0),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}
