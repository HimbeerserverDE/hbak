use std::{io, net};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An error occured on the local node: {0}")]
    HbakLocalNode(#[from] hbak_common::LocalNodeError),
    #[error("A network error occured: {0}")]
    HbakNetwork(#[from] hbak_common::NetworkError),
    #[error("Unable to parse volume identifier: {0}")]
    HbakVolumeParse(#[from] hbak_common::VolumeParseError),

    #[allow(clippy::enum_variant_names)]
    #[error("Unable to parse network address: {0}")]
    AddrParseError(#[from] net::AddrParseError),
    #[allow(clippy::enum_variant_names)]
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Hexadecimal decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

pub type Result<T> = std::result::Result<T, Error>;
