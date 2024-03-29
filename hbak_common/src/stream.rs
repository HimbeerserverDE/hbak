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

use crate::system;
use crate::LocalNodeError;

use std::collections::VecDeque;
use std::io::{self, BufRead, Read, Write};

use chacha20::XChaCha20;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::consts::U19;
use chacha20poly1305::{AeadCore, ChaChaPoly1305, Key, XChaCha20Poly1305};

/// The size of data chunks to encrypt or decrypt at a time in bytes (4096 KiB).
pub const CHUNKSIZE: usize = 4096 * 1024;

/// A `SnapshotStream` is a wrapper around a btrfs stream
/// that maps the stream to an encrypted version
/// preceeded by a randomly generated nonce.
pub struct SnapshotStream<B: BufRead> {
    inner: B,
    // The purpose of the `Option` is to allow `cipher` to be moved
    // when calling `encrypt_last` on it with just a mutable reference
    // to the `SnapshotStream` (so that `SnapshotStream::read_data`
    // can be called multiple times).
    cipher: Option<EncryptorBE32<XChaCha20Poly1305>>,
    buf: Vec<u8>,
}

impl<B: BufRead> SnapshotStream<B> {
    pub(crate) fn new<P: AsRef<[u8]>>(inner: B, passphrase: P) -> Result<Self, LocalNodeError> {
        let nonce = ChaChaPoly1305::<XChaCha20, U19>::generate_nonce(&mut OsRng);
        let mut key_array = [0; 32];
        system::hash_argon2id(&mut key_array, &nonce, passphrase)?;
        let key = Key::from_slice(&key_array);
        let cipher = EncryptorBE32::new(key, &nonce);

        // Accomodate authentication tag (16 bytes).
        let mut buf = Vec::with_capacity(16 + CHUNKSIZE);
        buf.extend(nonce);

        Ok(Self {
            inner,
            cipher: Some(cipher),
            buf,
        })
    }
}

impl<B: BufRead> Read for SnapshotStream<B> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let tmp = self.fill_buf()?;

        let n = buf.write(tmp)?;
        self.consume(n);

        Ok(n)
    }
}

impl<B: BufRead> BufRead for SnapshotStream<B> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
        if self.buf.is_empty() && self.inner.fill_buf().map(|b| !b.is_empty())? {
            let mut chunk = Vec::with_capacity(CHUNKSIZE);
            self.inner
                .by_ref()
                .take(CHUNKSIZE as u64)
                .read_to_end(&mut chunk)?;

            // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
            if self.inner.fill_buf().map(|b| !b.is_empty())? {
                self.buf.extend(
                    self.cipher
                        .as_mut()
                        .unwrap()
                        .encrypt_next(chunk.as_slice())
                        .map_err(io::Error::other)?,
                );
            } else {
                self.buf.extend(
                    self.cipher
                        .take()
                        .unwrap()
                        .encrypt_last(chunk.as_slice())
                        .map_err(io::Error::other)?,
                );
            }
        }

        Ok(&self.buf)
    }

    fn consume(&mut self, amt: usize) {
        // It's okay to panic if amt > self.buf.len()
        // since [`BufRead::consume`] requires the caller to pass in
        // amt <= self.buf.len() and silently clamping amt is probably bad
        // behavior.
        self.buf.drain(..amt);
    }
}

/// A `RecoveryStream` is a wrapper around an encrypted btrfs snapshot
/// that maps the stream to a decrypted version without the nonce.
///
/// Dropping a `RecoveryStream` flushes the last chunk to the underlying [`Write`]
/// ignoring any errors. You should handle errors where applicable
/// by calling [`RecoveryStream::close`] manually before dropping the stream.
pub struct RecoveryStream<W: Write, P: AsRef<[u8]>> {
    inner: W,
    passphrase: P,
    closed: bool,
    // The purpose of the `Option` is to allow `cipher` to be moved
    // when calling `encrypt_last` on it with just a mutable reference
    // to the `RecoveryStream` (so that `RecoveryStream::read_data`
    // can be called multiple times).
    cipher: Option<DecryptorBE32<XChaCha20Poly1305>>,
    buf: VecDeque<u8>,
}

impl<W: Write, P: AsRef<[u8]>> RecoveryStream<W, P> {
    pub(crate) fn new(inner: W, passphrase: P) -> Self {
        Self {
            inner,
            passphrase,
            closed: false,
            cipher: None,
            buf: VecDeque::with_capacity(16 + CHUNKSIZE), // Accomodate authentication tag (16 bytes).
        }
    }

    /// Reports whether the `RecoveryStream` is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Closes the `RecoveryStream`, writing all pending data to the underlying [`Write`].
    /// Fails with a 'broken pipe' error if the `RecoveryStream` is already closed.
    ///
    /// Further writes will return 'broken pipe' errors.
    ///
    /// This method is automatically called without error handling
    /// when the `RecoveryStream` is dropped.
    pub fn close(&mut self) -> Result<(), LocalNodeError> {
        if self.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
        }

        self.closed = true;

        self.buf.make_contiguous();

        // Read the authentication tag (16 bytes) too, otherwise decryption fails.
        let mut chunk = vec![0; 16 + CHUNKSIZE];
        let n = self.buf.read(&mut chunk)?;
        chunk.truncate(n);

        if let Some(cipher) = self.cipher.take() {
            let plain = cipher.decrypt_last(chunk.as_slice())?;
            self.inner.write_all(&plain)?;
        }

        // Uninitialized cipher is okay, nothing needs to be written.
        Ok(())
    }
}

impl<W: Write, P: AsRef<[u8]>> Write for RecoveryStream<W, P> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.is_closed() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }

        for byte in buf {
            if let Some(cipher) = &mut self.cipher {
                // Read the authentication tag (16 bytes) too, otherwise decryption fails.
                if self.buf.len() >= 16 + CHUNKSIZE {
                    let mut chunk = vec![0; 16 + CHUNKSIZE];
                    self.buf.read_exact(&mut chunk)?;

                    let plain = cipher
                        .decrypt_next(chunk.as_slice())
                        .map_err(io::Error::other)?;
                    self.inner.write_all(&plain)?;
                }
            } else if self.buf.len() >= 19 {
                let mut nonce_buf = [0; 19];
                self.buf.read_exact(&mut nonce_buf)?;

                let nonce = GenericArray::from_slice(&nonce_buf);
                let mut key_array = [0; 32];
                system::hash_argon2id(&mut key_array, nonce, &self.passphrase)
                    .map_err(io::Error::other)?;
                let key = Key::from_slice(&key_array);
                self.cipher = Some(DecryptorBE32::new(key, nonce));
            }

            self.buf.push_back(*byte);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write, P: AsRef<[u8]>> Drop for RecoveryStream<W, P> {
    fn drop(&mut self) {
        self.close().ok();
    }
}
