use crate::LocalNodeError;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

/// A `NodeConfig` contains metadata about a node
/// such as its name or the nodes it replicates to or stores
/// as well as authentication and encryption secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The device file the local btrfs file system is located at.
    pub device: String,
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
    pub const PATH: &str = "/etc/hbak.conf";

    /// Loads the configuration file of the current machine.
    pub fn load() -> Result<Self, LocalNodeError> {
        let mut f = File::open(Self::PATH)?;

        if f.metadata()?.permissions().mode() & 0o7077 > 0 {
            return Err(LocalNodeError::InsecurePerms);
        }

        let mut s = String::new();
        f.read_to_string(&mut s)?;

        Ok(toml::from_str(&s)?)
    }

    /// Saves the configuration to the configuration file on the current machine.
    pub fn save(&self) -> Result<(), LocalNodeError> {
        let s = toml::to_string_pretty(self)?;

        let mut f = OpenOptions::new()
            .create(true)
            .read(false)
            .write(true)
            .append(false)
            .truncate(true)
            .mode(0o0600)
            .open(Self::PATH)?;

        write!(f, "{}", s)?;
        Ok(())
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
///         must not include subvolumes owned by the local node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteNode {
    /// The network address and port of the node to push to.
    pub address: String,
    /// The volumes to interact with, see above for details.
    pub volumes: Vec<String>,
}

/// A `RemoteNodeAuth` defines authentication and authorization details
/// of a network node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteNodeAuth {
    /// The name of the remote node to apply the details to.
    pub node_name: String,
    /// A random value used by the remote node to compute the HMAC shared secret.
    pub verifier: Vec<u8>,
    /// The HMAC hash of verifier and passphrase for mutual authentication.
    pub hmac: Vec<u8>,
    /// The volumes the remote node is allowed to push.
    /// Must not include subvolumes owned by the local node.
    pub push: Vec<String>,
    /// The volumes the remote node is allowed to pull.
    pub pull: Vec<String>,
}
