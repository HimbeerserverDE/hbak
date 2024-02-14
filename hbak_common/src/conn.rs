use crate::config::RemoteNodeAuth;
use crate::message::*;
use crate::proto::Snapshot;
use crate::stream::CHUNKSIZE;
use crate::system;
use crate::{NetworkError, RemoteError};

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpStream};
use std::ops::DerefMut;
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::Duration;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use subtle::ConstantTimeEq;

/// Default TCP server port. Not officially reserved.
/// 406 is the sum of the ASCII codes for `hbak` and an offset to the 20000 port range.
pub const DEFAULT_PORT: u16 = 20406;

/// TCP connect timeout. Connection attempt is aborted if remote doesn't respond.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP read timeout. Internal value for [`StreamConn::data_sync`] receive thread cancellation.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

mod private {
    pub trait Sealed {}
}

/// A valid phase of a [`StreamConn`].
pub trait Phase: private::Sealed {}

impl private::Sealed for Idle {}
impl private::Sealed for Active {}
impl Phase for Idle {}
impl Phase for Active {}

/// The `Idle` phase of a [`StreamConn`].
///
/// No stream setup or timestamp synchronization has occured and transmissions are not allowed.
pub struct Idle;

/// The `Active` phase of a [`StreamConn`].
///
/// Timestamp synchronization has succeeded and transmissions are allowed and possibly in progress.
pub struct Active;

/// An `AuthConn` attempts mutual authentication between the local node
/// and a remote [`AuthServ`], transforming into a [`StreamConn`] on success.
pub struct AuthConn {
    stream: TcpStream,
}

impl AuthConn {
    /// Shorthand for `AuthConn::from(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?)`.
    pub fn new(addr: &SocketAddr) -> Result<Self, NetworkError> {
        Ok(TcpStream::connect_timeout(addr, CONNECT_TIMEOUT)?.into())
    }

    /// Performs mutual authentication and encryption of the connection
    /// using the provided node name and passphrase,
    /// returning a [`StreamConn`] on success.
    pub fn secure_stream<P: AsRef<[u8]>>(
        self,
        node_name: String,
        remote_node_name: String,
        passphrase: P,
    ) -> Result<StreamConn<Idle>, NetworkError> {
        // Consuming the `AuthConn` guarantees that this function can never be called again.

        let challenge = system::random_bytes(32);
        let nonce = system::random_bytes(19);
        let key;

        self.send_message(&CryptoMessage::Hello(Hello {
            node_name,
            challenge: challenge.clone(),
            nonce: nonce.clone(),
        }))?;

        match self.recv_message()? {
            CryptoMessage::ServerAuth(server_auth) => {
                let server_auth = server_auth?;

                key = system::derive_key(&server_auth.verifier, &passphrase)?;
                let server_proof = system::hash_hmac(&key, &challenge);

                if server_auth.proof.ct_eq(&server_proof).into() {
                    let proof = system::hash_hmac(&key, &server_auth.challenge);
                    self.send_message(&CryptoMessage::ClientAuth(Ok(ClientAuth { proof })))?;
                } else {
                    self.send_message(&CryptoMessage::ClientAuth(Err(RemoteError::AccessDenied)))?;
                    return Err(RemoteError::Unauthorized.into());
                }
            }
            _ => {
                self.send_message(&CryptoMessage::ClientAuth(Err(
                    RemoteError::IllegalTransition,
                )))?;
                return Err(NetworkError::IllegalTransition);
            }
        }

        match self.recv_message()? {
            CryptoMessage::Encrypt(encrypt) => {
                encrypt?;
                Ok(StreamConn::try_from_conn(
                    self.stream,
                    key,
                    nonce,
                    remote_node_name,
                )?)
            }
            _ => {
                self.send_message(&CryptoMessage::Error(RemoteError::IllegalTransition))?;
                Err(NetworkError::IllegalTransition)
            }
        }
    }

    fn send_message(&self, message: &CryptoMessage) -> Result<(), NetworkError> {
        let buf = bincode::serialize(message)?;
        (&self.stream).write_all(&buf)?;

        Ok(())
    }

    fn recv_message(&self) -> Result<CryptoMessage, NetworkError> {
        Ok(bincode::deserialize_from(&self.stream)?)
    }
}

impl From<TcpStream> for AuthConn {
    fn from(stream: TcpStream) -> Self {
        Self { stream }
    }
}

/// An `AuthServ` attempts mutual authentication between the local node
/// and a remote [`AuthConn`], transforming into a [`StreamConn`] on success.
pub struct AuthServ {
    stream: TcpStream,
}

impl AuthServ {
    /// Performs mutual authentication and encryption of the connection
    /// using the provided authentication storage,
    /// returning a [`StreamConn`] on success.
    pub fn secure_stream(
        self,
        auth_storage: impl IntoIterator<Item = RemoteNodeAuth>,
    ) -> Result<(StreamConn<Idle>, RemoteNodeAuth), NetworkError> {
        // Consuming the `AuthServ` guarantees that this function can never be called again.

        let challenge = system::random_bytes(32);
        let nonce;
        let key;
        let remote_node_auth;
        let remote_node_name;

        let client_proof;

        match self.recv_message()? {
            CryptoMessage::Hello(hello) => {
                let auth = auth_storage
                    .into_iter()
                    .find(|rna| rna.node_name == hello.node_name);

                if let Some(auth) = auth {
                    nonce = hello.nonce;
                    key = auth.key.clone();
                    remote_node_auth = auth;
                    remote_node_name = hello.node_name;

                    client_proof = system::hash_hmac(&key, &challenge);

                    let proof = system::hash_hmac(&key, &hello.challenge);

                    self.send_message(&CryptoMessage::ServerAuth(Ok(ServerAuth {
                        verifier: remote_node_auth.verifier.clone(),
                        challenge,
                        proof,
                    })))?;
                } else {
                    self.send_message(&CryptoMessage::ServerAuth(Err(RemoteError::AccessDenied)))?;
                    return Err(RemoteError::Unauthorized.into());
                }
            }
            _ => {
                self.send_message(&CryptoMessage::ServerAuth(Err(
                    RemoteError::IllegalTransition,
                )))?;
                return Err(NetworkError::IllegalTransition);
            }
        }

        match self.recv_message()? {
            CryptoMessage::ClientAuth(client_auth) => {
                let client_auth = client_auth?;

                if client_auth.proof.ct_eq(&client_proof).into() {
                    self.send_message(&CryptoMessage::Encrypt(Ok(())))?;
                    Ok((
                        StreamConn::try_from_conn(self.stream, key, nonce, remote_node_name)?,
                        remote_node_auth,
                    ))
                } else {
                    self.send_message(&CryptoMessage::Encrypt(Err(RemoteError::AccessDenied)))?;
                    Err(RemoteError::Unauthorized.into())
                }
            }
            _ => {
                self.send_message(&CryptoMessage::Encrypt(Err(RemoteError::IllegalTransition)))?;
                Err(NetworkError::IllegalTransition)
            }
        }
    }

    fn send_message(&self, message: &CryptoMessage) -> Result<(), NetworkError> {
        let buf = bincode::serialize(message)?;
        (&self.stream).write_all(&buf)?;

        Ok(())
    }

    fn recv_message(&self) -> Result<CryptoMessage, NetworkError> {
        Ok(bincode::deserialize_from(&self.stream)?)
    }
}

impl From<TcpStream> for AuthServ {
    fn from(stream: TcpStream) -> Self {
        Self { stream }
    }
}

/// A `StreamConn` can be used to exchange synchronization information (timestamps)
/// and provides circuit-switched access to snapshot storage.
/// It is the result of successful authentication and encryption
/// using an [`AuthConn`] or an [`AuthServ`].
pub struct StreamConn<P: Phase> {
    stream_read: Mutex<BufReader<TcpStream>>,
    stream_write: Mutex<BufWriter<TcpStream>>,
    encryptor: Mutex<EncryptorBE32<XChaCha20Poly1305>>,
    decryptor: Mutex<DecryptorBE32<XChaCha20Poly1305>>,
    remote_node_name: String,
    _phase: PhantomData<P>,
}

impl<P: Phase> StreamConn<P> {
    /// Returns the name of the remote node.
    pub fn remote_node_name(&self) -> &str {
        &self.remote_node_name
    }

    fn send_message(&self, message: &StreamMessage) -> Result<(), NetworkError> {
        let plaintext = bincode::serialize(message)?;
        let ciphertext = self
            .encryptor
            .lock()
            .unwrap()
            .encrypt_next(plaintext.as_slice())?;

        let mut w = self.stream_write.lock().unwrap();
        bincode::serialize_into(w.deref_mut(), &RawMessage(ciphertext))?;
        w.flush()?;

        Ok(())
    }

    fn recv_message(&self) -> Result<StreamMessage, NetworkError> {
        let ciphertext: RawMessage =
            bincode::deserialize_from(self.stream_read.lock().unwrap().deref_mut())?;
        let plaintext = self
            .decryptor
            .lock()
            .unwrap()
            .decrypt_next(ciphertext.0.as_slice())?;

        Ok(bincode::deserialize(&plaintext)?)
    }
}

impl StreamConn<Idle> {
    /// Constructs a new `StreamConn` from a [`std::net::TcpStream`],
    /// encryption key and nonce.
    pub(crate) fn try_from_conn(
        stream: TcpStream,
        key: Vec<u8>,
        nonce: Vec<u8>,
        remote_node_name: String,
    ) -> io::Result<Self> {
        stream.set_read_timeout(Some(READ_TIMEOUT))?;

        let key = Key::from_slice(&key);
        let nonce = GenericArray::from_slice(&nonce);

        Ok(Self {
            stream_read: Mutex::new(BufReader::with_capacity(2 * CHUNKSIZE, stream.try_clone()?)),
            stream_write: Mutex::new(BufWriter::with_capacity(2 * CHUNKSIZE, stream)),
            encryptor: Mutex::new(EncryptorBE32::new(key, nonce)),
            decryptor: Mutex::new(DecryptorBE32::new(key, nonce)),
            remote_node_name,
            _phase: PhantomData,
        })
    }

    /// Exchanges synchronization information (timestamps), returning an `Active` `StreamConn`
    /// that can send and receive data.
    pub fn meta_sync(
        self,
        sync_info: SyncInfo,
    ) -> Result<(StreamConn<Active>, SyncInfo), NetworkError> {
        self.send_message(&StreamMessage::SyncInfo(sync_info))?;

        match self.recv_message()? {
            StreamMessage::SyncInfo(sync_info) => Ok((
                StreamConn::<Active> {
                    stream_read: self.stream_read,
                    stream_write: self.stream_write,
                    encryptor: self.encryptor,
                    decryptor: self.decryptor,
                    remote_node_name: self.remote_node_name,
                    _phase: PhantomData,
                },
                sync_info,
            )),
            _ => {
                self.send_message(&StreamMessage::Error(RemoteError::IllegalTransition))?;
                Err(NetworkError::IllegalTransition)
            }
        }
    }
}

impl StreamConn<Active> {
    /// Transmits the passed [`std::io::Read`]s using their associated metadata.
    /// Receives remote transmissions using the provided stream setup closure.
    pub fn data_sync<R, W, I, S, F>(
        self,
        tx: I,
        rx_setup: S,
        rx_finish: F,
    ) -> Result<(), NetworkError>
    where
        R: Read,
        W: Write + Send,
        I: IntoIterator<Item = (R, Snapshot)> + Send,
        S: Fn(&Snapshot) -> Result<W, RemoteError> + Sync,
        F: Fn(Snapshot) -> Result<(), RemoteError> + Sync,
    {
        let stream_conn = RwLock::new(self);

        let mut stream = None;

        let mut handle = |stream_conn: &mut Self,
                          message: StreamMessage|
         -> Result<bool, NetworkError> {
            match message {
                StreamMessage::Stream(stream) => stream?,
                StreamMessage::Replicate(replicate) => {
                    if stream.is_none() {
                        match rx_setup(&replicate.snapshot) {
                            Ok(w) => {
                                stream = Some((w, replicate.snapshot));
                                stream_conn.send_message(&StreamMessage::Stream(Ok(())))?;
                            }
                            Err(e) => {
                                stream_conn.send_message(&StreamMessage::Stream(Err(e.clone())))?;
                                return Err(e.into());
                            }
                        }
                    } else {
                        stream_conn.send_message(&StreamMessage::Stream(Err(
                            RemoteError::AlreadyStreaming,
                        )))?;
                    }
                }
                StreamMessage::Chunk(chunk) => {
                    if let Some(stream) = &mut stream {
                        match stream.0.write_all(&chunk) {
                            Ok(_) => {}
                            Err(e) => {
                                stream_conn
                                    .send_message(&StreamMessage::Error(RemoteError::RxError))?;
                                return Err(e.into());
                            }
                        }
                    } else {
                        stream_conn
                            .send_message(&StreamMessage::Error(RemoteError::NotStreaming))?;
                    }
                }
                StreamMessage::End(end) => {
                    end?;

                    if let Some(current_stream) = stream.take() {
                        if let Err(e) = rx_finish(current_stream.1) {
                            stream_conn.send_message(&StreamMessage::Error(e.clone()))?;
                            return Err(e.into());
                        }
                    } else {
                        stream_conn
                            .send_message(&StreamMessage::Error(RemoteError::NotStreaming))?;
                    }
                }
                StreamMessage::Done => return Ok(true),
                StreamMessage::Error(e) => return Err(e.into()),
                _ => {
                    stream_conn
                        .send_message(&StreamMessage::Error(RemoteError::IllegalTransition))?;
                    return Err(NetworkError::IllegalTransition);
                }
            }

            Ok(false)
        };

        let send_chunk = |stream_conn: &Self, r: &mut R| -> Result<bool, NetworkError> {
            let mut chunk = vec![0; CHUNKSIZE];
            let n = r.read(&mut chunk)?;
            chunk.truncate(n);

            if !chunk.is_empty() {
                stream_conn.send_message(&StreamMessage::Chunk(chunk))?;
                Ok(true)
            } else {
                stream_conn.send_message(&StreamMessage::End(Ok(())))?;
                Ok(false)
            }
        };

        let local_done = Mutex::new(false);
        thread::scope(|s| {
            let tx = s.spawn(|| -> Result<(), NetworkError> {
                for (mut r, snapshot) in tx.into_iter() {
                    stream_conn
                        .read()
                        .unwrap()
                        .send_message(&StreamMessage::Replicate(snapshot.into()))?;

                    while match send_chunk(&stream_conn.read().unwrap(), &mut r) {
                        Ok(is_data_left) => is_data_left,
                        Err(e) => {
                            stream_conn
                                .read()
                                .unwrap()
                                .send_message(&StreamMessage::End(Err(RemoteError::TxError)))?;
                            return Err(e);
                        }
                    } {}
                }

                Ok(())
            });
            let rx = s.spawn(|| -> Result<(), NetworkError> {
                let mut remote_done = false;

                while !*local_done.lock().unwrap() || !remote_done {
                    let message = match stream_conn.read().unwrap().recv_message() {
                        Ok(message) => message,
                        Err(NetworkError::Bincode(bincode_err)) => match *bincode_err {
                            bincode::ErrorKind::Io(io_err)
                                if io_err.kind() == io::ErrorKind::WouldBlock
                                    || io_err.kind() == io::ErrorKind::TimedOut =>
                            {
                                continue
                            }
                            bincode::ErrorKind::Io(io_err)
                                if io_err.kind() == io::ErrorKind::UnexpectedEof
                                    && *local_done.lock().unwrap()
                                    && remote_done =>
                            {
                                return Ok(())
                            }
                            _ => return Err(bincode_err.into()),
                        },
                        Err(e) => return Err(e),
                    };

                    if handle(&mut stream_conn.write().unwrap(), message)? {
                        remote_done = true;
                    }
                }

                Ok(())
            });

            tx.join().unwrap()?;

            *local_done.lock().unwrap() = true;
            stream_conn
                .read()
                .unwrap()
                .send_message(&StreamMessage::Done)?;

            rx.join().unwrap()?;

            Ok(())
        })
    }
}
