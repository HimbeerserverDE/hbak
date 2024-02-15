// hbakd is an hbak server providing clients with push and pull access.
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
