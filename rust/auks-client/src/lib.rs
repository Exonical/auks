//! Rust client for the AUKS daemon wire protocol.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::thread;

use auks_config::ClientConfig;
use auks_cred::messages;
use auks_cred::{Cred, CredError};
use auks_krb5::{Context, Error as Krb5Error, cred_blob, read_message, write_message};
use auks_proto::{Message, MessageType, ProtoError, Reader};
use thiserror::Error;

/// Errors returned by the Rust AUKS client.
#[derive(Debug, Error)]
pub enum Error {
    /// A Kerberos operation failed.
    #[error(transparent)]
    Krb5(#[from] Krb5Error),
    /// Network or stream I/O failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// AUKS wire data was malformed.
    #[error(transparent)]
    Proto(#[from] ProtoError),
    /// A credential wire record was malformed.
    #[error(transparent)]
    Cred(#[from] CredError),
    /// The daemon returned an error status.
    #[error("auksd returned error status {0}")]
    Daemon(i32),
    /// No readable Kerberos credential cache was available.
    #[error("no readable Kerberos credential cache: {0}")]
    NoCcache(String),
    /// The daemon returned an unexpected reply.
    #[error("unexpected AUKS reply {0:?}")]
    UnexpectedReply(MessageType),
}

enum AttemptError {
    Retry(Error),
    Return(Error),
}

/// A configured AUKS daemon client.
#[derive(Debug, Clone)]
pub struct Client {
    config: ClientConfig,
    ccache: Option<String>,
}

impl Client {
    /// Creates a client using the configured default credential cache.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            ccache: None,
        }
    }

    /// Selects a credential cache by full name.
    pub fn with_ccache(mut self, name: impl Into<String>) -> Self {
        self.ccache = Some(name.into());
        self
    }

    /// Sends an encoded request and decodes its reply.
    pub fn request(&self, request: &Message) -> Result<Message, Error> {
        let servers = std::iter::once(&self.config.primary)
            .chain(self.config.secondary.iter())
            .collect::<Vec<_>>();
        let mut last_error = None;
        for retry in 0..self.config.retries.max(1) {
            for server in &servers {
                match self.try_request(server, request) {
                    Ok(reply) => return Ok(reply),
                    Err(AttemptError::Retry(error)) => last_error = Some(error),
                    Err(AttemptError::Return(error)) => return Err(error),
                }
            }
            if retry + 1 < self.config.retries.max(1) {
                thread::sleep(self.config.delay);
            }
        }
        Err(last_error.unwrap_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "no AUKS servers configured",
            ))
        }))
    }

    fn try_request(
        &self,
        server: &auks_config::Server,
        request: &Message,
    ) -> Result<Message, AttemptError> {
        let port = server
            .port
            .parse::<u16>()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid TCP port {}", server.port),
                )
            })
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let addresses = (server.address.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let mut stream = None;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.config.timeout) {
                Ok(value) => {
                    stream = Some(value);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let stream = stream
            .ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "no resolved server address",
                    )
                })
            })
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let context = Context::new().map_err(|error| AttemptError::Retry(error.into()))?;
        let cache = match &self.ccache {
            Some(name) => context
                .resolve_ccache(name)
                .map_err(|error| AttemptError::Retry(error.into()))?,
            None => context
                .default_ccache()
                .map_err(|error| AttemptError::Retry(error.into()))?,
        };
        let client = cache
            .principal()
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let server_principal = context
            .parse_name(&server.principal)
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let local = match stream
            .local_addr()
            .map_err(|error| AttemptError::Retry(error.into()))?
        {
            SocketAddr::V4(value) => *value.ip(),
            SocketAddr::V6(_) => {
                return Err(AttemptError::Retry(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 local endpoint is unsupported",
                ))));
            }
        };
        let peer = match stream
            .peer_addr()
            .map_err(|error| AttemptError::Retry(error.into()))?
        {
            SocketAddr::V4(value) => *value.ip(),
            SocketAddr::V6(_) => {
                return Err(AttemptError::Retry(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 remote endpoint is unsupported",
                ))));
            }
        };
        let mut auth = context
            .auth_context()
            .map_err(|error| AttemptError::Retry(error.into()))?;
        auth.set_addrs(local, peer)
            .map_err(|error| AttemptError::Retry(error.into()))?;
        auth.set_flags(auks_krb5::AUTH_CONTEXT_DO_SEQUENCE)
            .map_err(|error| AttemptError::Retry(error.into()))?;
        let mut fd = stream.as_raw_fd();
        auth.sendauth(&mut fd, &client, &server_principal, &cache)
            .map_err(|error| AttemptError::Retry(error.into()))?;
        if self.config.nat {
            auth.set_dummy_addrs()
                .map_err(|error| AttemptError::Return(error.into()))?;
        }
        let ciphertext = auth
            .mk_priv(&request.encode())
            .map_err(|error| AttemptError::Return(error.into()))?;
        write_message(&context, &mut fd, &ciphertext)
            .map_err(|error| AttemptError::Return(error.into()))?;
        let ciphertext =
            read_message(&context, &mut fd).map_err(|error| AttemptError::Return(error.into()))?;
        let plaintext = auth
            .rd_priv(&ciphertext)
            .map_err(|error| AttemptError::Return(error.into()))?;
        let reply =
            Message::decode(&plaintext).map_err(|error| AttemptError::Return(error.into()))?;
        if let Ok(close) = auth.mk_priv(&messages::close().encode()) {
            let _ = write_message(&context, &mut fd, &close);
        }
        Ok(reply)
    }

    /// Adds the credential represented by a ccache to the daemon.
    pub fn add_cred(&self, ccache: Option<&str>) -> Result<(), Error> {
        let context = Context::new()?;
        let cache = match ccache.or(self.ccache.as_deref()) {
            Some(name) => context.resolve_ccache(name),
            None => context.default_ccache(),
        }
        .map_err(|error| Error::NoCcache(error.to_string()))?;
        let blob =
            cred_blob::get(&context, &cache).map_err(|error| Error::NoCcache(error.to_string()))?;
        let requester = ccache.map_or_else(|| self.clone(), |name| self.clone().with_ccache(name));
        let reply = requester.request(&messages::add_request(&blob))?;
        self.expect_empty_reply(reply, MessageType::AddReply)
    }

    /// Retrieves a credential by Unix user ID.
    pub fn get_cred(&self, uid: u32) -> Result<Cred, Error> {
        let reply = self.request(&messages::get_request(uid))?;
        match reply.ty {
            MessageType::GetReply => messages::decode_get_reply(&reply).map_err(Error::from),
            MessageType::ErrorReply => Err(Self::daemon_error(&reply)),
            ty => Err(Error::UnexpectedReply(ty)),
        }
    }

    /// Removes a credential by Unix user ID.
    pub fn remove_cred(&self, uid: u32) -> Result<(), Error> {
        let reply = self.request(&messages::remove_request(uid))?;
        self.expect_empty_reply(reply, MessageType::RemoveReply)
    }

    /// Checks daemon reachability and protocol compatibility.
    pub fn ping(&self) -> Result<(), Error> {
        let reply = self.request(&messages::ping())?;
        self.expect_empty_reply(reply, MessageType::PingReply)
    }

    fn expect_empty_reply(&self, reply: Message, expected: MessageType) -> Result<(), Error> {
        match reply.ty {
            ty if ty == expected => Ok(()),
            MessageType::ErrorReply => Err(Self::daemon_error(&reply)),
            ty => Err(Error::UnexpectedReply(ty)),
        }
    }

    fn daemon_error(reply: &Message) -> Error {
        let mut reader = Reader::new(&reply.body);
        Error::Daemon(reader.unpack_int().unwrap_or(-1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auks_config::{ClientConfig, Server};
    use std::net::TcpListener;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    fn config(primary: u16, secondary: u16) -> ClientConfig {
        ClientConfig {
            primary: Server {
                host: "127.0.0.1".into(),
                address: "127.0.0.1".into(),
                port: primary.to_string(),
                principal: "host/localhost@EXAMPLE.COM".into(),
            },
            secondary: Some(Server {
                host: "127.0.0.1".into(),
                address: "127.0.0.1".into(),
                port: secondary.to_string(),
                principal: "host/localhost@EXAMPLE.COM".into(),
            }),
            cross_realm: None,
            nat: false,
            retries: 2,
            timeout: Duration::from_millis(50),
            delay: Duration::from_secs(1),
            helper_script: None,
        }
    }

    #[test]
    fn retries_primary_and_secondary() {
        let primary = TcpListener::bind(("127.0.0.1", 0)).expect("primary listener");
        let secondary = TcpListener::bind(("127.0.0.1", 0)).expect("secondary listener");
        let primary_port = primary.local_addr().expect("primary address").port();
        let secondary_port = secondary.local_addr().expect("secondary address").port();
        let primary_count = Arc::new(AtomicUsize::new(0));
        let secondary_count = Arc::new(AtomicUsize::new(0));
        let primary_count_thread = Arc::clone(&primary_count);
        let secondary_count_thread = Arc::clone(&secondary_count);
        let primary_thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let _ = primary.accept().expect("primary connection");
                primary_count_thread.fetch_add(1, Ordering::Relaxed);
            }
        });
        let secondary_thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let _ = secondary.accept().expect("secondary connection");
                secondary_count_thread.fetch_add(1, Ordering::Relaxed);
            }
        });
        let client = Client::new(config(primary_port, secondary_port));
        let started = Instant::now();
        let error = client.ping().expect_err("closed ports");
        assert!(matches!(error, Error::Io(_) | Error::Krb5(_)));
        assert!(started.elapsed() >= Duration::from_secs(1));
        primary_thread.join().expect("primary thread");
        secondary_thread.join().expect("secondary thread");
        assert_eq!(primary_count.load(Ordering::Relaxed), 2);
        assert_eq!(secondary_count.load(Ordering::Relaxed), 2);
    }
}
