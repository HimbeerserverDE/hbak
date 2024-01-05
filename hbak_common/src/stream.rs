use std::io::BufRead;

use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::XChaCha20Poly1305;

/// A `SnapshotStream` is a wrapper around a btrfs stream
/// that implements [`std::io::Read`] and maps the stream
/// to an encrypted version including the nonce.
pub struct SnapshotStream<R: BufRead> {
    pub(crate) inner: R,
    pub(crate) cipher: EncryptorBE32<XChaCha20Poly1305>,
    pub(crate) header: Vec<u8>,
}

impl<R: Read> SnapshotStream<R> {}

todo!("Encrypt: Use a BufRead and read in chunks of e.g. 1024 bytes; use encrypt_last method if the actual read size is less than that");
