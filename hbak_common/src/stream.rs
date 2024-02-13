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
    header: VecDeque<u8>,
    buf: VecDeque<u8>,
}

impl<B: BufRead> SnapshotStream<B> {
    pub(crate) fn new<P: AsRef<[u8]>>(inner: B, passphrase: P) -> Result<Self, LocalNodeError> {
        let nonce = ChaChaPoly1305::<XChaCha20, U19>::generate_nonce(&mut OsRng);
        let mut key_array = [0; 32];
        system::hash_argon2id(&mut key_array, &nonce, passphrase)?;
        let key = Key::from_slice(&key_array);
        let cipher = EncryptorBE32::new(key, &nonce);

        Ok(Self {
            inner,
            cipher: Some(cipher),
            header: nonce.to_vec().into(),
            buf: VecDeque::new(),
        })
    }
}

impl<B: BufRead> Read for SnapshotStream<B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;

        while let Some(byte) = self.header.pop_front() {
            if n >= buf.len() {
                break;
            }

            buf[n] = byte;
            n += 1;
        }

        // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
        while self.inner.fill_buf().map(|b| !b.is_empty())? {
            let mut chunk = vec![0; CHUNKSIZE];
            let n = self.inner.read(&mut chunk)?;
            chunk.truncate(n);

            // Stable version of [`BufRead::has_data_left`] (tracking issue: #86423).
            if self.inner.fill_buf().map(|b| !b.is_empty())? {
                self.buf.extend(
                    self.cipher
                        .as_mut()
                        .unwrap()
                        .encrypt_next(chunk.as_slice())
                        .map_err(io::Error::other)?
                        .into_iter(),
                );
            } else {
                self.buf.extend(
                    self.cipher
                        .take()
                        .unwrap()
                        .encrypt_last(chunk.as_slice())
                        .map_err(io::Error::other)?
                        .into_iter(),
                );
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
            buf: VecDeque::new(),
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

        let mut chunk = vec![0; CHUNKSIZE];
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
                if self.buf.len() >= CHUNKSIZE {
                    let mut chunk = vec![0; CHUNKSIZE];
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
