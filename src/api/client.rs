//! Connecting to the control plane, on whichever transport this platform has.

use crate::api::pb::control_client::ControlClient;
use crate::config::Endpoint;
use crate::error::{Error, Result};

pub type Client = ControlClient<tonic::transport::Channel>;

/// Dial the daemon.
///
/// A connection failure is reported as [`Error::Unreachable`] rather than as a
/// transport error: from an operator's point of view "nothing is listening
/// there" is a lifecycle problem, not a network one, and `vgctl` turns it into
/// exit code 4.
pub async fn connect(endpoint: &Endpoint) -> Result<Client> {
    match endpoint {
        Endpoint::Tcp(addr) => ControlClient::connect(format!("http://{addr}"))
            .await
            .map_err(|e| unreachable(endpoint, e)),

        #[cfg(unix)]
        Endpoint::Unix(path) => {
            use hyper_util::rt::TokioIo;
            use tokio::net::UnixStream;

            let path = path.clone();
            // The URI is ignored — the connector decides where the bytes go —
            // but tonic still requires a syntactically valid authority.
            let channel = tonic::transport::Endpoint::try_from("http://vanguard.invalid")
                .map_err(|e| Error::Config(e.to_string()))?
                .connect_with_connector(tower::service_fn(move |_| {
                    let path = path.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))
                    }
                }))
                .await
                .map_err(|e| unreachable(endpoint, e))?;
            Ok(ControlClient::new(channel))
        }

        #[cfg(not(unix))]
        Endpoint::Unix(path) => Err(Error::Config(format!(
            "unix sockets are unavailable on this platform; \
             configure runtime.control_addr instead of {}",
            path.display()
        ))),
    }
}

fn unreachable(endpoint: &Endpoint, err: impl std::fmt::Display) -> Error {
    Error::Unreachable {
        endpoint: endpoint.to_string(),
        detail: err.to_string(),
    }
}
