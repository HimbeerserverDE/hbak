use crate::LocalNodeError;

use std::fs;

use serde::{Deserialize, Serialize};

/// A `NodeConfig` contains metadata about a node
/// such as its name or the nodes it replicates to or stores
/// as well as authentication and encryption secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The name of the [`Node`].
    pub node_name: String,
    /// The subvolumes owned by the [`Node`], i.e. the subvolumes
    /// that originate from it.
    pub subvols: Vec<String>,
    /// The encryption passphrase for the subvolumes owned by this node.
    /// The backups can only be decrypted using this passphrase.
    ///
    /// **DO NOT reuse this passphrase across nodes as this undermines
    /// the end-to-end aspect of the encryption.**
    ///
    /// **Remember this passphrase at all costs. Losing it makes it impossible
    /// to recover any of the backups.**
    pub passphrase: String,
    /// The nodes to push (encrypted) owned or replicated volumes to.
    pub push: Vec<RemoteNode>,
    /// The nodes to pull (encrypted) replicas of their owned
    /// or replicated volumes from.
    pub pull: Vec<RemoteNode>,
    /// The authentication details and privileges of other nodes
    /// for verification when they connect.
    pub auth: Vec<RemoteNodeAuth>,
}

impl NodeConfig {
    const PATH: &str = "/etc/hbak.conf";

    pub fn load() -> Result<Self, LocalNodeError> {
        let s = fs::read_to_string(Self::PATH)?;
        Ok(toml::from_str(&s)?)
    }
}

/// A `RemoteNode` defines a network node that can be interacted with.
/// Backups can be pushed to or pulled from a `RemoteNode`.
///
/// The meaning of the `vols` field differs based on the context
/// the `RemoteNode` appears in:
///
/// * Push: The volumes to push to the remote node.
/// * Pull: The volumes to pull from the remote node,
///         must not include snapshots owned by the local node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteNode {
    /// The network address and port of the node to push to.
    pub address: String,
    /// The shared secret for mutual authentication.
    pub secret: String,
    /// The volumes to interact with, see above for details.
    pub volumes: Vec<String>,
}

/// A `RemoteNodeAuth` defines authentication and authorization details
/// of a network node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteNodeAuth {
    /// The shared secret for mutual authentication.
    pub secret: String,
    /// The volumes the remote node is allowed to push.
    /// Must not include subvolumes owned by the local node.
    pub push: Vec<String>,
    /// The volumes the remote node is allowed to pull.
    pub pull: Vec<String>,
}
