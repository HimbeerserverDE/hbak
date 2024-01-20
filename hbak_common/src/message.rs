use crate::proto::{LatestSnapshots, Snapshot, Volume};
use crate::NetworkError;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A network message to be exchanged between `hbak` and `hbakd`
/// initializing mutual authentication and encryption.
///
/// Messages aren't bound to a particular receiver role unless otherwise noted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CryptoMessage {
    /// Start the authentication process. This message is serverbound.
    Hello(Hello),
    /// Server identity proof and challenge. This message is clientbound.
    ServerAuth(Result<ServerAuth, NetworkError>),
    /// Client identity proof. This message is serverbound.
    ClientAuth(Result<ClientAuth, NetworkError>),
    /// Authentication successful. Further traffic is encrypted. This message is clientbound.
    Encrypt(Result<(), NetworkError>),
}

/// Start the authentication process. This message is serverbound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// The name of the client node.
    pub node_name: String,
    /// A random challenge for clientbound authentication.
    pub challenge: Vec<u8>,
    /// A random nonce for transport encryption.
    pub nonce: Vec<u8>,
}

/// Server identity proof and challenge. This message is clientbound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerAuth {
    /// A random challenge for serverbound authentication.
    pub challenge: Vec<u8>,
    /// The server's identity proof, HMAC(shared_secret, client_challenge).
    pub proof: Vec<u8>,
}

/// Client identity proof. This message is serverbound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientAuth {
    /// The client's identity proof, HMAC(shared_secret, server_challenge).
    pub proof: Vec<u8>,
}

/// A network message to be exchanged between `hbak` and `hbakd`
/// controlling data streaming.
///
/// Messages aren't bound to a particular receiver role unless otherwise noted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StreamMessage {
    /// The latest known timestamps of full and incremental snapshots that may be sent.
    SyncInfo(SyncInfo),
    /// Request to stream a certain snapshot.
    Transmit(Transmit),
    /// Stream setup successful. Followed by the data.
    Stream(Result<(), NetworkError>),
    /// Sending a chunk of maximum size.
    Chunk(Result<(), NetworkError>),
    /// Sending the final (dynamically sized) chunk.
    Final(Result<usize, NetworkError>),
}

/// The latest known timestamps of full and incremental snapshots that may be sent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncInfo {
    /// A map of accepted volumes and their latest known timestamps
    /// of full and incremental snapshots.
    pub volumes: HashMap<Volume, LatestSnapshots>,
}

/// Request to stream a certain snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transmit {
    /// The snapshot to stream to.
    pub snapshot: Snapshot,
}