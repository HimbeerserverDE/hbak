use crate::NetworkError;

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// TCP connect timeout. Connection attempt is aborted if remote doesn't respond.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// An `AuthConn` attempts mutual authentication between the local node
/// and a remote [`AuthServ`], transforming into a [`StreamConn`] on success.
#[derive(Debug)]
pub struct AuthConn {
    stream: TcpStream,
}

impl AuthConn {
    /// Shorthand for `AuthConn::from(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?)`.
    pub fn new(addr: &SocketAddr) -> Result<Self, NetworkError> {
        Ok(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?.into())
    }
}

impl From<TcpStream> for AuthConn {
    fn from(stream: TcpStream) -> Self {
        Self { stream }
    }
}

/// An `AuthServ` attempts mutual authentication between the local node
/// and a remote [`AuthConn`], transforming into a [`StreamConn`] on success.
#[derive(Debug)]
pub struct AuthServ {
    stream: TcpStream,
}

impl From<TcpStream> for AuthServ {
    fn from(stream: TcpStream) -> Self {
        Self { stream }
    }
}

/// A `StreamConn` can be used to exchange synchronization information (timestamps)
/// and provides circuit-switched access to snapshot storage.
/// It is the result of successful authentication and encryption
/// using an [`AuthConn`] or an [`AuthServ`].
#[derive(Debug)]
pub struct StreamConn {
    stream: TcpStream,
    encryptor: EncryptorBE32<XChaCha20Poly1305>,
    decryptor: DecryptorBE32<XChaCha20Poly1305>,
}
