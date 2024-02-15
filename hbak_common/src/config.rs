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

use crate::proto::Volume;
use crate::LocalNodeError;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

/// A `NodeConfig` contains metadata about a node
/// such as its name or the nodes it replicates to or stores
/// as well as authentication and encryption secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// The device file the local btrfs file system is located at.
    pub device: String,
    /// The network address `hbakd` binds to. The default is `[::]:20406` (dual stack).
    pub bind_addr: Option<SocketAddr>,
    /// The name of the [`crate::proto::Node`].
    pub node_name: String,
    /// The subvolumes owned by the [`crate::proto::Node`], i.e. the subvolumes
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
    /// The remote nodes to interact with by pushing to or pulling from them.
    pub remotes: Vec<RemoteNode>,
    /// The authentication details and privileges of other nodes
    /// for verification when they connect.
    pub auth: Vec<RemoteNodeAuth>,
}

impl NodeConfig {
    pub const PATH: &'static str = "/etc/hbak.conf";

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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteNode {
    /// The network address and port of the node to push to.
    pub address: String,
    /// The volumes to push to the remote node.
    pub push: Vec<Volume>,
    /// The volumes to pull from the remote node,
    /// must not include subvolumes owned by the local node.
    pub pull: Vec<Volume>,
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
    pub key: Vec<u8>,
    /// The volumes the remote node is allowed to push.
    /// Must not include subvolumes owned by the local node.
    pub push: Vec<Volume>,
    /// The volumes the remote node is allowed to pull.
    pub pull: Vec<Volume>,
}
