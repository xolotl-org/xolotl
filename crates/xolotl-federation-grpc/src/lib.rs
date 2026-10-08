//! Publisher-side gRPC admission and wire conversion for unreleased protocol v1.
//! Hosts provide a TLS listener, authoritative peer policy and durable store.

#![forbid(unsafe_code)]

/// Transport limits and pinned outbound TLS routes.
pub mod config;
mod delivery;
mod driver;
mod incoming;
mod object_source;
mod remote_endpoint;
mod runtime;
mod session;
mod subscriber;
mod subscriber_driver;
mod tls;
mod wire;

pub use delivery::RemoteSyncFailure;

pub use wire::ServedCapability;

/// Current unreleased Federation Session protocol.
pub const FEDERATION_PROTOCOL_VERSION: u32 = 1;

pub use driver::{FederationGrpcPublisherServer, FederationGrpcPublisherStream};
pub use incoming::{
    FederationIncoming, FederationTlsConnectInfo, FederationTlsStream, federation_tls_incoming,
};
pub use object_source::FederationGrpcObjectSource;
pub use remote_endpoint::{
    DurableOperationIdHash, FederationCallCodec, FederationCallIdentity, FederationCallPrincipal,
    FederationCallPrincipalBinding, FederationCallSession, FederationCallSessionProvider,
    FederationRemoteBinding, FederationRemoteEndpoint, FederationRemoteKey, FederationRemoteTiming,
    JsonCallCodec, RawBytesCallCodec,
};
pub use runtime::FederationGrpcRuntime;
pub use session::{
    FederationCallInvoker, FederationGrpcPublisherSession, FederationLocalCredentials,
    FederationObjectReader, FederationPeerPolicy, ObjectReadFuture,
};
pub use subscriber::{
    FederationGrpcSubscriberSession, FederationHostedSubjectCredentials,
    FederationInvitationReceipt, FederationSubscriberEvent, FederationSubscriberResult,
};
pub use subscriber_driver::{FederationGrpcSubscriberClient, FederationSubscriberServices};
pub use tls::FederationTlsChannel;

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};
    use xolotl_federation::{
        FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRootKey,
        FederationSessionTranscript, RootSignaturePurpose, verify_federation_peer_proof,
    };
    use xolotl_proto::xolotl::v1::federation as pb;

    use super::{config::FederationGrpcConfig, wire};

    #[test]
    fn wire_rejects_previous_identity_and_digest_width() {
        assert!(wire::node(vec![1; 32]).is_err());
        assert!(wire::node(vec![1; 48]).is_ok());
        assert!(
            wire::position(pb::Position {
                sequence: 1,
                digest: vec![2; 32],
            })
            .is_err()
        );
        assert!(
            wire::position(pb::Position {
                sequence: 1,
                digest: vec![2; 48],
            })
            .is_ok()
        );
    }

    #[test]
    fn hello_and_authenticate_bind_both_root_authorized_online_keys() -> Result<()> {
        let a_root_key = FederationRootKey::generate()?;
        let b_root_key = FederationRootKey::generate()?;
        let a_online_key = FederationOnlineKey::generate()?;
        let b_online_key = FederationOnlineKey::generate()?;
        let a = make_hello(&a_root_key, &a_online_key, [1; 32])?;
        let b = make_hello(&b_root_key, &b_online_key, [2; 32])?;

        ensure!(super::FEDERATION_PROTOCOL_VERSION == 1);
        for version in [0, 2] {
            let mut unsupported_protocol = a.clone();
            unsupported_protocol.protocol_version = version;
            ensure!(wire::hello(unsupported_protocol).is_err());
        }
        let mut unknown_service = a.clone();
        unknown_service.served_capabilities = 16;
        ensure!(wire::hello(unknown_service).is_err());
        let mut advertised = a.clone();
        advertised.served_capabilities = 15;
        let advertised = wire::hello(advertised)?;
        let original = wire::hello(a.clone())?;
        let remote = wire::hello(b.clone())?;
        ensure!(
            wire::hello_capabilities_digest(&original, &remote)
                != wire::hello_capabilities_digest(&advertised, &remote)
        );
        ensure!(
            wire::hello_capabilities_digest(&remote, &original)
                != wire::hello_capabilities_digest(&remote, &advertised)
        );

        let mut unknown_required = a.clone();
        unknown_required.required_features.push(99);
        ensure!(wire::hello(unknown_required).is_err());
        let mut wrong_node = a.clone();
        wrong_node.node_id = vec![3; 48];
        ensure!(wire::hello(wrong_node).is_err());
        let mut impossible_frame_limit = a.clone();
        impossible_frame_limit.max_frame_bytes = 4096;
        impossible_frame_limit.max_batch_bytes = 1024;
        ensure!(wire::hello(impossible_frame_limit).is_err());

        let a = wire::hello(a)?;
        let b = wire::hello(b)?;
        let capabilities = wire::hello_capabilities_digest(&a, &b);
        let session = FederationSessionTranscript::new(
            a.node,
            b.node,
            a.nonce,
            b.nonce,
            [9; 48],
            capabilities,
        )?;
        for (hello, key) in [(&a, &a_online_key), (&b, &b_online_key)] {
            let signed = key.sign_session(hello.node, &hello.authorization, &session)?;
            let signed = wire::authenticate(pb::Authenticate {
                online_signature: signed,
            })?;
            let proof = verify_federation_peer_proof(
                &hello.root,
                hello.node,
                &hello.authorization,
                &hello.root_signature,
                &session,
                &signed,
                150,
            )?;
            ensure!(proof.node_id() == hello.node);
            let changed = FederationSessionTranscript::new(
                a.node,
                b.node,
                a.nonce,
                b.nonce,
                [9; 48],
                wire::hello_capabilities_digest(&advertised, &b),
            )?;
            ensure!(
                verify_federation_peer_proof(
                    &hello.root,
                    hello.node,
                    &hello.authorization,
                    &hello.root_signature,
                    &changed,
                    &signed,
                    150,
                )
                .is_err()
            );
        }
        ensure!(
            wire::authenticate(pb::Authenticate {
                online_signature: vec![0; 32],
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn configuration_must_fit_full_pq_hello() {
        let config = FederationGrpcConfig {
            max_frame_bytes: 4096,
            max_batch_bytes: 1024,
            ..FederationGrpcConfig::default()
        };
        assert!(config.validate().is_err());
        assert!(FederationGrpcConfig::default().validate().is_ok());
    }

    #[test]
    fn finished_call_may_retain_completion_after_output_expires() -> Result<()> {
        let receipt = pb::CallInspected {
            request: 1,
            call: Some(pb::CallRef {
                target: vec![1; 48],
                id: vec![2; 32],
            }),
            status: pb::CallStatus::Finished as i32,
            control_revision: 3,
            authority_revision: 1,
            reserved_until_ms: 100,
            execution_deadline_ms: 200,
            result_retained_until_ms: 300,
            result: None,
            unresolved_effect_ids: Vec::new(),
            cancellation_requested: false,
            kernel_cancel_accepted: false,
            execution_stopped: true,
        };
        let inspected = wire::call_inspected(receipt.clone())?;
        ensure!(inspected.status == xolotl_federation::CallStatus::Finished);
        ensure!(inspected.result.is_none());
        let mut inconsistent = receipt;
        inconsistent.status = pb::CallStatus::Unproven as i32;
        inconsistent.result = Some(pb::PersistedCallResult {
            succeeded: true,
            output: Vec::new(),
            output_digest: vec![0; 48],
            failure_code: String::new(),
        });
        ensure!(wire::call_inspected(inconsistent).is_err());
        Ok(())
    }

    fn make_hello(
        root_key: &FederationRootKey,
        online_key: &FederationOnlineKey,
        nonce: [u8; 32],
    ) -> Result<pb::Hello> {
        let root = root_key.root()?;
        let authorization =
            FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, 200)?;
        let authorization_bytes = authorization.encode();
        let root_signature = root_key.sign(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization_bytes,
        )?;
        Ok(pb::Hello {
            protocol_version: super::FEDERATION_PROTOCOL_VERSION,
            node_id: root.node_id().as_bytes().to_vec(),
            max_frame_bytes: 1024 * 1024,
            max_in_flight: 16,
            max_batch_records: 128,
            max_batch_bytes: 512 * 1024,
            root_descriptor: root.encode(),
            online_authorization: authorization_bytes,
            root_signature,
            nonce: nonce.to_vec(),
            required_features: Vec::new(),
            served_capabilities: 0,
        })
    }
}
