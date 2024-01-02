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
}

impl NodeConfig {
    const PATH: &str = "/etc/hbak.conf";

    pub fn load() -> Result<Self, LocalNodeError> {
        let s = fs::read_to_string(Self::PATH)?;
        Ok(toml::from_str(&s)?)
    }
}
