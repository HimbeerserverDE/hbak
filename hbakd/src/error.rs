use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An error occured on the local node: {0}")]
    HbakLocalNode(#[from] hbak_common::LocalNodeError),
    #[error("A network error occured: {0}")]
    HbakNetwork(#[from] hbak_common::NetworkError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Unable to set signal handler: {0}")]
    Ctrlc(#[from] ctrlc::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
