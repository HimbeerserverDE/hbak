use crate::LocalNodeError;

use std::collections::VecDeque;
use std::io::{BufRead, Write};

use chacha20::XChaCha20;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::consts::U19;
use chacha20poly1305::{AeadCore, ChaChaPoly1305, Key, XChaCha20Poly1305};
use sha2::Sha256;

/// The size of data chunks to encrypt or decrypt at a time in bytes.
pub const CHUNKSIZE: usize = 4096;

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
    header: VecDeque<u8>,
    buf: VecDeque<u8>,
}

impl<B: BufRead> SnapshotStream<B> {
    pub(crate) fn new<P: AsRef<[u8]>>(inner: B, passphrase: P) -> Self {
        let nonce = ChaChaPoly1305::<XChaCha20, U19>::generate_nonce(&mut OsRng);
        let key_array =
            pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_ref(), &nonce, 600000);
        let key = Key::from_slice(&key_array);
        let cipher = EncryptorBE32::new(key, &nonce);

        Self {
            inner,
            cipher: Some(cipher),
            header: nonce.to_vec().into(),
            buf: VecDeque::new(),
        }
    }

    /// Reads ciphertext from the `SnapshotStream`.
    /// Returns a length of zero when there is nothing left to read
    /// or if the passed buffer has a length of zero.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, LocalNodeError> {
        let mut n = 0;

        while let Some(byte) = self.header.pop_front() {
            if n >= buf.len() {
                break;
            }

            buf[n] = byte;
            n += 1;
        }

        while let Some(byte) = self.buf.pop_front() {
            if n >= buf.len() {
                break;
            }

            buf[n] = byte;
            n += 1;
        }

        // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
        while self.inner.fill_buf().map(|b| !b.is_empty())? {
            let mut chunk = [0; CHUNKSIZE];
            let n = self.inner.read(&mut chunk)?;
            let chunk = &chunk[..n];

            // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
            if self.inner.fill_buf().map(|b| !b.is_empty())? {
                self.buf.extend(
                    self.cipher
                        .as_mut()
                        .unwrap()
                        .encrypt_next(chunk)?
                        .into_iter(),
                );
            } else {
                self.buf
                    .extend(self.cipher.take().unwrap().encrypt_last(chunk)?.into_iter());
                break;
            }
        }

        Ok(n)
    }

    /// Calls [`SnapshotStream::read_data`] repeatedly
    /// until all data has been written to the provided [`std::io::Write`].
    pub fn write_to<W: Write>(mut self, w: &mut W) -> Result<(), LocalNodeError> {
        loop {
            let mut chunk = [0; CHUNKSIZE];
            let n = self.read_data(&mut chunk)?;
            if n == 0 {
                break;
            }
            let chunk = &chunk[..n];

            w.write_all(chunk)?;
        }

        Ok(())
    }
}

/// A `RecoveryStream` is a wrapper around an encrypted btrfs snapshot
/// that maps the stream to a decrypted version without the nonce.
pub struct RecoveryStream<B: BufRead> {
    inner: B,
    // The purpose of the `Option` is to allow `cipher` to be moved
    // when calling `encrypt_last` on it with just a mutable reference
    // to the `RecoveryStream` (so that `RecoveryStream::read_data`
    // can be called multiple times).
    cipher: Option<DecryptorBE32<XChaCha20Poly1305>>,
    buf: VecDeque<u8>,
}

impl<B: BufRead> RecoveryStream<B> {
    pub(crate) fn new<P: AsRef<[u8]>>(mut inner: B, passphrase: P) -> Result<Self, LocalNodeError> {
        let mut nonce_buf = [0; 19];
        inner.read_exact(&mut nonce_buf)?;

        let nonce = GenericArray::from_slice(&nonce_buf);
        let key_array = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_ref(), nonce, 600000);
        let key = Key::from_slice(&key_array);
        let cipher = DecryptorBE32::new(key, nonce);

        Ok(Self {
            inner,
            cipher: Some(cipher),
            buf: VecDeque::new(),
        })
    }

    /// Reads plaintext from the `RecoveryStream`.
    /// Returns a length of zero when there is nothing left to read
    /// or if the passed buffer has a length of zero.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, LocalNodeError> {
        let mut n = 0;

        // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
        while self.inner.fill_buf().map(|b| !b.is_empty())? {
            let mut chunk = [0; CHUNKSIZE];
            let n = self.inner.read(&mut chunk)?;
            let chunk = &chunk[..n];

            // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
            if self.inner.fill_buf().map(|b| !b.is_empty())? {
                self.buf.extend(
                    self.cipher
                        .as_mut()
                        .unwrap()
                        .decrypt_next(chunk)?
                        .into_iter(),
                );
            } else {
                self.buf
                    .extend(self.cipher.take().unwrap().decrypt_last(chunk)?.into_iter());
                break;
            }
        }

        while let Some(byte) = self.buf.pop_front() {
            if n >= buf.len() {
                break;
            }

            buf[n] = byte;
            n += 1;
        }

        Ok(n)
    }

    /// Calls [`RecoveryStream::read_data`] repeatedly
    /// until all data has been written to the provided [`std::io::Write`].
    pub fn write_to<W: Write>(mut self, w: &mut W) -> Result<(), LocalNodeError> {
        loop {
            let mut chunk = [0; CHUNKSIZE];
            let n = self.read_data(&mut chunk)?;
            if n == 0 {
                break;
            }
            let chunk = &chunk[..n];

            w.write_all(chunk)?;
        }

        Ok(())
    }
}
