use crate::message::Target;
use crate::{NetworkError, RemoteError};

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::XChaCha20Poly1305;

/// TCP connect timeout. Connection attempt is aborted if remote doesn't respond.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The valid states of an [`AuthConn`].
#[derive(Debug, Default, Eq, PartialEq)]
enum AuthConnState {
    /// Authentication has not started.
    #[default]
    Idle,
    /// A `Hello` message has been sent. Awaiting the `ServerAuth` response.
    Handshake {
        /// The challenge sent in the `Hello` message.
        challenge: Vec<u8>,
        /// The nonce for transport encryption.
        nonce: Vec<u8>,
    },
    /// A `ServerAuth` message has been received and a `ClientAuth` reaction has been sent.
    /// Awaiting the `Encrypt` response.
    Proof {
        /// The nonce for transport encryption.
        nonce: Vec<u8>,
    },
    /// An `Encrypt` message has been received and encryption has been configured.
    /// Further plaintext reads or writes are not allowed. Transformation is imminent.
    Encrypted,
    /// Authentication or encryption setup has failed. The connection should be terminated.
    Failed(RemoteError),
}

/// The valid states of an [`AuthServ`].
#[derive(Debug, Default, Eq, PartialEq)]
enum AuthServState {
    /// Authentication has not started. Awaiting the `Hello` request.
    #[default]
    Idle,
    /// A `Hello` message has been received and a `ServerAuth` response has been sent.
    /// Awaiting the `ClientAuth` reaction.
    Proof {
        /// The challenge sent in the `ServerAuth` response.
        challenge: Vec<u8>,
        /// The nonce for transport encryption.
        nonce: Vec<u8>,
    },
    /// An `Encrypt` message has been sent and encryption has been configured.
    /// Further plaintext reads or writes are not allowed.
    Encrypted,
    /// Authentication or encryption setup has failed. The connection should be terminated.
    Failed(RemoteError),
}

/// The valid states of a [`StreamConn`].
#[derive(Debug, Default, Eq, PartialEq)]
enum StreamConnState {
    /// No streaming in progress. Synchronization information has not been received,
    /// but has been sent to the remote node.
    #[default]
    Idle,
    /// No streaming in progress. Synchronization information has been received.
    /// Streaming may be initiated.
    Ready,
    /// Transmission in progress. Reception may be initiated by the remote node,
    /// but no transmission may be initiated by the local node.
    Transmitting(Target),
    /// Reception in progress. Transmission may be initiated by the local node,
    /// but no reception may be initiated by the remote node.
    Receiving(Target),
    /// Transmission and reception in progress. Neither may be initiated.
    FullDuplex {
        /// The destination the local transmission is writing to on the remote node.
        tx: Target,
        /// The destination the remote transmission is writing to on the local node.
        rx: Target,
    },
    /// No streaming in progress. Further transmissions are not allowed.
    /// The local node has finished replication to the remote node.
    FinishSent,
    /// No streaming in progress. Further receptions are not allowed.
    /// The remote node has finished replication to the local node.
    FinishReceived,
    /// Transmission in progress. Further receptions are not allowed.
    /// The remote node has finished replication to the local node.
    FinishTransmitting,
    /// Reception in progress. Further transmissions are not allowed.
    /// The local node has finished replication to the remote node.
    FinishReceiving,
    /// No streaming in progress. Further initiations are not allowed.
    /// Both nodes have fully synchronized with each other.
    Finished,
    /// Stream setup is denied or has failed. No reception in progress.
    /// No new transmissions may be initiated
    /// until the `Ready` or `Receiving` state is entered.
    Failed(RemoteError),
    /// Stream setup is denied or has failed. Reception in progress.
    /// No new transmissions may be initiated
    /// until the `Ready` or `Receiving` state is entered.
    RecvFailed(RemoteError),
}

/// An `AuthConn` attempts mutual authentication between the local node
/// and a remote [`AuthServ`], transforming into a [`StreamConn`] on success.
pub struct AuthConn {
    stream: TcpStream,
    state: AuthConnState,
}

impl AuthConn {
    /// Shorthand for `AuthConn::from(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?)`.
    pub fn new(addr: &SocketAddr) -> Result<Self, NetworkError> {
        Ok(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?.into())
    }
}

impl From<TcpStream> for AuthConn {
    fn from(stream: TcpStream) -> Self {
        Self {
            stream,
            state: AuthConnState::default(),
        }
    }
}

/// An `AuthServ` attempts mutual authentication between the local node
/// and a remote [`AuthConn`], transforming into a [`StreamConn`] on success.
pub struct AuthServ {
    stream: TcpStream,
    state: AuthServState,
}

impl From<TcpStream> for AuthServ {
    fn from(stream: TcpStream) -> Self {
        Self {
            stream,
            state: AuthServState::default(),
        }
    }
}

/// A `StreamConn` can be used to exchange synchronization information (timestamps)
/// and provides circuit-switched access to snapshot storage.
/// It is the result of successful authentication and encryption
/// using an [`AuthConn`] or an [`AuthServ`].
pub struct StreamConn {
    stream: TcpStream,
    encryptor: EncryptorBE32<XChaCha20Poly1305>,
    decryptor: DecryptorBE32<XChaCha20Poly1305>,
}
