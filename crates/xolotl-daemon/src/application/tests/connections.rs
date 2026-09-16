use super::*;
use crate::application::connection::ApplicationConnection;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tonic::transport::server::Connected;
use xolotl_proto::xolotl::v1::application as pb;

const WAIT: Duration = Duration::from_secs(2);

async fn application() -> Result<ApplicationGateway> {
    let boot = Arc::new(Bootstrap::in_memory());
    boot.kernel
        .state
        .write_set(&profile::profile_path("app")?, value(1)?)
        .await?;
    ApplicationGateway::start_at(&config(), Some("127.0.0.1:0"), boot, ObjectStore::new())
        .await?
        .context("application listener should start")
}

async fn read_until_closed(socket: &mut TcpStream) -> Result<()> {
    tokio::time::timeout(WAIT, async {
        let mut buffer = [0_u8; 256];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .context("connection stayed open after application shutdown")?
}

#[tokio::test]
async fn shutdown_closes_connection_waiting_for_http2_preface() -> Result<()> {
    let application = application().await?;
    let address = application.listen_address;
    let mut socket = TcpStream::connect(address).await?;
    // The SETTINGS header proves tonic owns the accepted connection. The client
    // deliberately sends no preface, so no request handler can observe shutdown.
    let mut settings_header = [0_u8; 9];
    tokio::time::timeout(WAIT, socket.read_exact(&mut settings_header)).await??;
    ensure!(settings_header[3] == 4, "expected initial HTTP/2 SETTINGS");
    let task_abort_handles: Vec<_> = application
        .tasks
        .iter()
        .map(JoinHandle::abort_handle)
        .collect();
    tokio::time::timeout(WAIT, application.shutdown())
        .await
        .context("shutdown waited for the listener drain timeout")?;
    ensure!(
        task_abort_handles
            .iter()
            .all(tokio::task::AbortHandle::is_finished)
    );
    read_until_closed(&mut socket).await?;
    ensure!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[tokio::test]
async fn connection_shutdown_is_sticky_for_every_io_operation() -> Result<()> {
    for shutdown_before_accept in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (stream, peer) = listener.accept().await?;
        let (shutdown, receiver) = watch::channel(shutdown_before_accept);
        let mut connection = ApplicationConnection::new(stream, receiver);
        ensure!(connection.connect_info().remote_addr() == Some(peer));
        ensure!(connection.connect_info().local_addr() == Some(listener.local_addr()?));
        if !shutdown_before_accept {
            shutdown.send_replace(true);
        }
        let mut buffer = [0_u8; 1];
        let read_error = connection
            .read(&mut buffer)
            .await
            .err()
            .context("read must fail")?;
        let write_error = connection
            .write(&[1])
            .await
            .err()
            .context("write must fail")?;
        let vectored_error = connection
            .write_vectored(&[io::IoSlice::new(&[1])])
            .await
            .err()
            .context("vectored write must fail")?;
        let flush_error = connection.flush().await.err().context("flush must fail")?;
        let shutdown_error = connection
            .shutdown()
            .await
            .err()
            .context("shutdown must fail")?;
        for error in [
            read_error,
            write_error,
            vectored_error,
            flush_error,
            shutdown_error,
        ] {
            ensure!(error.kind() == io::ErrorKind::ConnectionAborted);
        }
        drop(connection);
        let mut client = client;
        read_until_closed(&mut client).await?;
    }
    Ok(())
}

#[tokio::test]
async fn wrapped_connections_preserve_peer_and_profile_authority_checks() -> Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let token = "application-connection-authority-test";
    let token_hash = blake3::hash(token.as_bytes()).to_hex().to_string();
    let document = serde_json::from_value(json!({
        "profile_name": "app", "version": 1,
        "credentials": [{
            "credential_id": "key", "principal_id": "client",
            "verifier": {"kind": "bearer", "token_hash": token_hash}
        }],
        "identity_mappings": [{"principal_id": "client", "identity_path": "process://client"}],
        "registered_hosts": ["app.example:9445"]
    }))?;
    boot.kernel
        .state
        .write_set(&profile::profile_path("app")?, document)
        .await?;
    let application =
        ApplicationGateway::start_at(&config(), Some("127.0.0.1:0"), boot, ObjectStore::new())
            .await?
            .context("application listener should start")?;
    let endpoint =
        tonic::transport::Endpoint::from_shared(format!("http://{}", application.listen_address))?
            .connect_timeout(WAIT)
            .timeout(WAIT);
    let request = || -> Result<tonic::Request<pb::DescribeRequest>> {
        let mut request = tonic::Request::new(pb::DescribeRequest {});
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse()?);
        Ok(request)
    };
    // Channel's AddOrigin layer overrides the generated client's URI origin.
    let channel = endpoint
        .clone()
        .origin("http://app.example:9445".parse()?)
        .connect()
        .await?;
    let mut client = pb::application_gateway_client::ApplicationGatewayClient::new(channel);
    let described = client.describe(request()?).await?.into_inner();
    ensure!(described.profile_name == "app" && described.profile_rev == 1);
    let channel = endpoint
        .origin("http://other.example:9445".parse()?)
        .connect()
        .await?;
    let mut wrong_authority =
        pb::application_gateway_client::ApplicationGatewayClient::new(channel);
    let error = wrong_authority
        .describe(request()?)
        .await
        .err()
        .context("wrong authority must fail")?;
    ensure!(error.code() == tonic::Code::PermissionDenied);
    tokio::time::timeout(WAIT, application.shutdown()).await?;
    Ok(())
}
