// hbak_common is the main hbak library implementing the protocol shared logic.
// Copyright (C) 2024  Himbeer <himbeerserverde@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::proto::{LatestSnapshots, Snapshot, Volume};
use crate::RemoteError;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A network message containing raw data such as an encrypted inner message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct RawMessage(pub Vec<u8>);

/// A network message to be exchanged between `hbak` and `hbakd`
/// initializing mutual authentication and encryption.
///
/// Messages aren't bound to a particular receiver role unless otherwise noted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CryptoMessage {
    /// Start the authentication process. This message is serverbound.
    Hello(Hello),
    /// Server identity proof and challenge. This message is clientbound.
    ServerAuth(Result<ServerAuth, RemoteError>),
    /// Client identity proof. This message is serverbound.
    ClientAuth(Result<ClientAuth, RemoteError>),
    /// Authentication successful. Further traffic is encrypted. This message is clientbound.
    Encrypt(Result<(), RemoteError>),
    /// Protocol error independent of the operation or state context.
    Error(RemoteError),
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
    /// The verifier needed to compute the shared secret on the client.
    pub verifier: Vec<u8>,
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
    /// Request to stream to a certain snapshot.
    Replicate(Target),
    /// Stream setup successful. Followed by the data.
    Stream(Result<(), RemoteError>),
    /// Sending a chunk of dynamic size.
    Chunk(Vec<u8>),
    /// Transmission completed or failed.
    End(Result<(), RemoteError>),
    /// No further transmissions will follow. Used for connection shutdown synchronization.
    Done,
    /// Protocol error independent of the operation or state context.
    Error(RemoteError),
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
pub struct Target {
    /// The snapshot to stream to.
    pub snapshot: Snapshot,
}

impl From<Snapshot> for Target {
    fn from(snapshot: Snapshot) -> Self {
        Self { snapshot }
    }
}
