//! Shared test helpers for the integration tests in `tests/`.
//!
//! Each `tests/*.rs` file is compiled as a separate test
//! binary; to share code between them, each one declares
//! `mod common;` and pulls what it needs from
//! [`PskHandshake`] and friends. This module is *not* part
//! of the published crate — it is only compiled as part of
//! the test binaries, so the heavy crypto dependencies it
//! pulls in (`chacha20poly1305`, `hkdf`, `sha2`) stay out
//! of the published surface area.
//!
//! `PskHandshake` is a faithful, minimal
//! implementation of the same pattern documented in
//! `examples/encrypted.rs`: a `pea2pea` `Handshake` that
//! uses a hard-coded pre-shared key, a 32-byte nonce
//! exchange, HKDF-SHA256 session-key derivation, and a
//! length-prefixed ChaCha20-Poly1305 stream wrap. The
//! "production" version of this is the application's
//! responsibility (Noise / TLS); the test only needs a
//! working example to exercise the `Handshake` wiring.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use peaveil::{Connection, ConnectionSide, Handshake, Pea2Pea};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};

const PSK: [u8; 32] = [0x42; 32];
const NONCE_LEN: usize = 32;
const CHUNK_NONCE_LEN: usize = 12;
const CHUNK_TAG_LEN: usize = 16;
const LEN_LEN: usize = 4;

#[derive(Clone)]
pub struct PskHandshake {
    pub inner: Arc<peashape::Node>,
}

impl Pea2Pea for PskHandshake {
    fn node(&self) -> &peaveil::pea2pea::Node {
        self.inner.p2p()
    }
}

impl Handshake for PskHandshake {
    const TIMEOUT_MS: u64 = 5_000;

    async fn perform_handshake(&self, mut conn: Connection) -> io::Result<Connection> {
        let is_initiator = conn.side() == ConnectionSide::Initiator;
        let stream = self.take_stream(&mut conn);
        let (mut read, mut write) = split(stream);

        let mut my_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut my_nonce);
        let mut peer_nonce = [0u8; NONCE_LEN];
        if is_initiator {
            write.write_all(&my_nonce).await?;
            read.read_exact(&mut peer_nonce).await?;
        } else {
            read.read_exact(&mut peer_nonce).await?;
            write.write_all(&my_nonce).await?;
        }

        let (salt, info) = if my_nonce <= peer_nonce {
            (&my_nonce[..], &peer_nonce[..])
        } else {
            (&peer_nonce[..], &my_nonce[..])
        };
        let hk = Hkdf::<Sha256>::new(Some(salt), &PSK);
        let mut session_key = [0u8; 32];
        hk.expand(info, &mut session_key)
            .map_err(|_| io::Error::other("hkdf expand failed"))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));

        let wrapped = BiStream {
            read: DecStream::new(read, cipher.clone()),
            write: EncStream::new(write, cipher),
        };
        self.return_stream(&mut conn, wrapped);
        Ok(conn)
    }
}

pub struct EncStream<W: AsyncWrite + Unpin> {
    inner: W,
    cipher: ChaCha20Poly1305,
    pending: Option<(usize, BytesMut)>,
}

impl<W: AsyncWrite + Unpin> EncStream<W> {
    pub fn new(inner: W, cipher: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            cipher,
            pending: None,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for EncStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((pt_len, ref mut framed)) = this.pending {
            while !framed.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, framed) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(n)) => framed.advance(n),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.pending = None;
            return Poll::Ready(Ok(pt_len));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut chunk_nonce = [0u8; CHUNK_NONCE_LEN];
        OsRng.fill_bytes(&mut chunk_nonce);
        let ct = this
            .cipher
            .encrypt(Nonce::from_slice(&chunk_nonce), buf)
            .map_err(|_| io::Error::other("AEAD encrypt failed"))?;
        let mut framed = BytesMut::with_capacity(LEN_LEN + CHUNK_NONCE_LEN + ct.len());
        framed.put_u32((CHUNK_NONCE_LEN + ct.len()) as u32);
        framed.extend_from_slice(&chunk_nonce);
        framed.extend_from_slice(&ct);
        let pt_len = buf.len();
        while !framed.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &framed) {
                Poll::Ready(Ok(0)) => {
                    this.pending = Some((pt_len, framed));
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Ok(n)) => framed.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending = Some((pt_len, framed));
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(pt_len))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct DecStream<R: AsyncRead + Unpin> {
    inner: R,
    cipher: ChaCha20Poly1305,
    /// Decrypted plaintext not yet consumed by the caller.
    pending: BytesMut,
    /// Accumulated encrypted bytes that do not yet form a
    /// complete chunk. Survives across `Pending` returns so
    /// that partial reads of the length header or body are
    /// not lost when the inner stream yields `Pending`
    /// mid-chunk (the read-side analogue of `EncStream`'s
    /// `pending`).
    inbound: BytesMut,
}

impl<R: AsyncRead + Unpin> DecStream<R> {
    pub fn new(inner: R, cipher: ChaCha20Poly1305) -> Self {
        Self {
            inner,
            cipher,
            pending: BytesMut::new(),
            inbound: BytesMut::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecStream<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. Drain any plaintext left over from a previously
        //    decrypted chunk before pulling another one.
        if !self.pending.is_empty() {
            let n = std::cmp::min(self.pending.len(), buf.remaining());
            buf.put_slice(&self.pending[..n]);
            self.pending.advance(n);
            return Poll::Ready(Ok(()));
        }

        // 2. Loop: try to parse a complete chunk from
        //    `inbound`; if there isn't one yet, read more
        //    bytes from the inner stream into `inbound` and
        //    retry. Because `inbound` lives on `self`, a
        //    `Pending` return from the inner stream does not
        //    lose bytes already consumed (a partial length
        //    header or a partial body).
        loop {
            if self.inbound.len() >= LEN_LEN {
                let len =
                    u32::from_be_bytes(self.inbound[..LEN_LEN].try_into().expect("LEN_LEN bytes"))
                        as usize;
                if len < CHUNK_NONCE_LEN + CHUNK_TAG_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AEAD chunk shorter than nonce + tag",
                    )));
                }
                if self.inbound.len() >= LEN_LEN + len {
                    // A complete chunk is buffered; consume
                    // its header and body, then decrypt.
                    self.inbound.advance(LEN_LEN);
                    let body = self.inbound.split_to(len);
                    let (chunk_nonce, ct) = body.split_at(CHUNK_NONCE_LEN);
                    let pt = self
                        .cipher
                        .decrypt(Nonce::from_slice(chunk_nonce), ct)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "AEAD decrypt failed")
                        })?;
                    let n = std::cmp::min(pt.len(), buf.remaining());
                    buf.put_slice(&pt[..n]);
                    if n < pt.len() {
                        self.pending = BytesMut::from(&pt[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
            // Not enough bytes for a complete chunk; read more
            // from the inner stream into `inbound`.
            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.inbound.extend_from_slice(&tmp[..n]);
                    // loop: retry parsing with the new bytes
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub struct BiStream<R, W> {
    read: R,
    write: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for BiStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for BiStream<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}
