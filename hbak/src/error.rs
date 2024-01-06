use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An error has occured on the local node: {0}")]
    HbakLocalNode(#[from] hbak_common::LocalNodeError),

    #[allow(clippy::enum_variant_names)]
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Hexadecimal decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, Error>;
