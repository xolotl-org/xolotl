//! Bind the transport-independent object receiver to one authenticated Session.

use core::future::Future;
use std::pin::Pin;

use tonic::Code;
use xolotl_federation::{
    FederationError, FederationObjectChunkSource, FederationSubject, ObjectReadPage,
    ObjectReadRequest, ObjectReceiveSpec,
};

use crate::FederationGrpcSubscriberClient;

/// A read source fixed to one provider, subject and grant. The Session checks
/// its registered subject context on each request; the receiver checks the
/// complete object and records verification before the host binds a reference.
#[derive(Clone)]
pub struct FederationGrpcObjectSource {
    client: FederationGrpcSubscriberClient,
    context_id: u32,
    spec: ObjectReceiveSpec,
}

impl FederationGrpcObjectSource {
    /// `context_id` is zero for this node or an ID returned by the Session's
    /// hosted-subject registration. A nonzero ID alone is not an authority.
    pub fn new(
        client: FederationGrpcSubscriberClient,
        context_id: u32,
        spec: ObjectReceiveSpec,
    ) -> Result<Self, FederationError> {
        spec.validate(client.local_node())?;
        if spec.provider != client.peer_node()
            || matches!(
                (&spec.subject, context_id),
                (FederationSubject::Node(_), id) if id != 0
            )
            || matches!(
                (&spec.subject, context_id),
                (FederationSubject::Hosted(_), 0)
            )
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(Self {
            client,
            context_id,
            spec,
        })
    }

    /// The exact receive binding used when constructing this source.
    pub fn spec(&self) -> &ObjectReceiveSpec {
        &self.spec
    }
}

impl FederationObjectChunkSource for FederationGrpcObjectSource {
    type Read<'a> =
        Pin<Box<dyn Future<Output = Result<ObjectReadPage, FederationError>> + Send + 'a>>;

    fn read(&self, request: ObjectReadRequest) -> Self::Read<'_> {
        Box::pin(async move {
            if request.authenticated_presenter != self.client.local_node()
                || request.subject != self.spec.subject
                || request.grant != self.spec.grant
                || request.expected_revision != self.spec.grant_revision
                || request.blob != self.spec.blob
            {
                return Err(FederationError::Conflict);
            }
            self.client
                .read_object_as(self.context_id, request)
                .await
                .map_err(map_object_status)
        })
    }
}

fn map_object_status(status: tonic::Status) -> FederationError {
    match status.code() {
        Code::InvalidArgument => FederationError::Invalid("remote object read rejected"),
        Code::PermissionDenied | Code::Unauthenticated | Code::NotFound => {
            FederationError::Unauthorized
        }
        Code::AlreadyExists | Code::Aborted | Code::FailedPrecondition => FederationError::Conflict,
        Code::ResourceExhausted => FederationError::Capacity,
        Code::DataLoss => FederationError::Corrupt,
        Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable => {
            FederationError::Indeterminate
        }
        _ => FederationError::Storage("remote object read failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::sync::Arc;
    use xolotl_federation::{Digest, FederationNodeId, ObjectGrantId, ObjectTransferId};
    use xolotl_types::BlobRef;

    #[test]
    fn transport_failures_preserve_retry_and_authority_classes() {
        assert_eq!(
            map_object_status(tonic::Status::unavailable("private peer detail")),
            FederationError::Indeterminate
        );
        assert_eq!(
            map_object_status(tonic::Status::permission_denied("private peer detail")),
            FederationError::Unauthorized
        );
        assert_eq!(
            map_object_status(tonic::Status::resource_exhausted("private peer detail")),
            FederationError::Capacity
        );
    }

    #[tokio::test]
    async fn source_refuses_another_provider_or_receive_binding() -> anyhow::Result<()> {
        let local = FederationNodeId::from_bytes([1; 48]);
        let peer = FederationNodeId::from_bytes([2; 48]);
        let (commands, _receiver) = tokio::sync::mpsc::channel(1);
        let (client, _termination) = FederationGrpcSubscriberClient::from_live(
            commands,
            local,
            peer,
            crate::FederationGrpcRuntime::new(
                crate::config::FederationGrpcConfig::default(),
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?
            .worker_pool(),
            crate::config::FederationGrpcConfig::default(),
            1,
            1024,
        );
        let spec = ObjectReceiveSpec {
            provider: peer,
            subject: FederationSubject::Node(local),
            grant: ObjectGrantId::new(7)?,
            grant_revision: 2,
            blob: BlobRef {
                hash: "a".repeat(96),
                size: 8,
                mime: None,
            },
            owner: Digest::from_bytes([3; 48]),
        };
        ensure!(matches!(
            FederationGrpcObjectSource::new(
                client.clone(),
                0,
                ObjectReceiveSpec {
                    provider: FederationNodeId::from_bytes([4; 48]),
                    ..spec.clone()
                }
            ),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            FederationGrpcObjectSource::new(client.clone(), 1, spec.clone()),
            Err(FederationError::Unauthorized)
        ));
        let source = FederationGrpcObjectSource::new(client, 0, spec.clone())?;
        let rejected = source
            .read(ObjectReadRequest {
                authenticated_presenter: local,
                subject: spec.subject,
                transfer: ObjectTransferId::from_bytes([5; 16]),
                grant: spec.grant,
                expected_revision: spec.grant_revision + 1,
                blob: spec.blob,
                offset: 0,
                max_bytes: 8,
            })
            .await;
        ensure!(rejected == Err(FederationError::Conflict));
        Ok(())
    }
}
