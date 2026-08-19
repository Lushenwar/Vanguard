//! Binding and serving the control plane.
//!
//! Binding is separate from serving so that a caller can learn the address it
//! actually got before traffic starts. That matters for `127.0.0.1:0`, where
//! the kernel picks the port: the alternative — bind, read the port, drop,
//! rebind — is a race, and races in test harnesses are how flaky suites start.

use std::future::Future;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::api::pb::control_server::ControlServer;
use crate::api::{ControlService, Handle};
use crate::config::Endpoint;
use crate::error::{Error, Result};

/// A bound, not-yet-serving listener.
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, std::path::PathBuf),
}

impl Listener {
    /// Where this listener actually ended up, which is not necessarily what was
    /// asked for.
    pub fn endpoint(&self) -> Result<Endpoint> {
        match self {
            Listener::Tcp(l) => Ok(Endpoint::Tcp(
                l.local_addr()
                    .map_err(|e| Error::Config(e.to_string()))?
                    .to_string(),
            )),
            #[cfg(unix)]
            Listener::Unix(_, path) => Ok(Endpoint::Unix(path.clone())),
        }
    }
}

pub async fn bind(endpoint: &Endpoint) -> Result<Listener> {
    match endpoint {
        Endpoint::Tcp(addr) => {
            Ok(Listener::Tcp(TcpListener::bind(addr).await.map_err(
                |e| Error::Config(format!("runtime.control_addr {addr:?}: {e}")),
            )?))
        }

        #[cfg(unix)]
        Endpoint::Unix(path) => {
            reclaim_stale_socket(path).await?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Ok(Listener::Unix(
                tokio::net::UnixListener::bind(path)?,
                path.clone(),
            ))
        }

        #[cfg(not(unix))]
        Endpoint::Unix(path) => Err(Error::Config(format!(
            "unix sockets are unavailable on this platform; \
             configure runtime.control_addr instead of {}",
            path.display()
        ))),
    }
}

/// Serve until `shutdown` resolves.
pub async fn serve(
    listener: Listener,
    handle: Handle,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let service = ControlServer::new(ControlService::new(handle));

    match listener {
        Listener::Tcp(l) => Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(l), shutdown)
            .await
            .map_err(|e| Error::Config(e.to_string())),

        #[cfg(unix)]
        Listener::Unix(l, path) => {
            use tokio_stream::wrappers::UnixListenerStream;

            let result = Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(UnixListenerStream::new(l), shutdown)
                .await
                .map_err(|e| Error::Config(e.to_string()));

            // A clean exit removes its own socket, so the next start does not
            // have to go through the stale-socket path at all.
            let _ = std::fs::remove_file(&path);
            result
        }
    }
}

/// Remove a socket file left behind by a crashed daemon, and refuse to start if
/// one is actually live.
///
/// This is the "stale PID lockout" in the risk taxonomy. Probing by connecting
/// is the reliable test: a PID file can be recycled by an unrelated process,
/// whereas a socket that accepts a connection unambiguously has a listener.
#[cfg(unix)]
async fn reclaim_stale_socket(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    match tokio::net::UnixStream::connect(path).await {
        Ok(_) => Err(Error::Config(format!(
            "another vanguardd is already listening on {}",
            path.display()
        ))),
        Err(_) => {
            tracing::warn!(path = %path.display(), "removing stale socket");
            std::fs::remove_file(path)?;
            Ok(())
        }
    }
}
