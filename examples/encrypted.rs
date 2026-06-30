//! The privacy-correct end-to-end pattern: encrypt and
//! authenticate the TCP connection with a `pea2pea`
//! [`Handshake`].
//!
//! `peaveil` deliberately does not ship its own
//! encryption (see the crate-level "threat model"
//! section), but the underlying `pea2pea` transport is
//! fully under the caller's control. The recommended
//! pattern is:
//!
//! 1. Construct a `peaveil::Node`.
//! 2. Reach the underlying `pea2pea::Node` via
//!    [`Node::p2p`], wrap it in your own type that
//!    implements the [`Handshake`] trait, and call
//!    [`Handshake::enable_handshake`].
//! 3. Call [`Node::spawn`]; from that point on, every
//!    inbound and outbound connection performs the
//!    handshake before any `peaveil` frame is read or
//!    written.
//!
//! This example shows the **minimum viable** version: a
//! pre-shared key, a 32-byte nonce exchange, HKDF-SHA256
//! for session-key derivation, and a length-prefixed
//! ChaCha20-Poly1305 stream wrap. The peaveil *content* is
//! still plaintext bytes (a peer sample), but the entire
//! TCP stream is now encrypted and authenticated, so a
//! passive observer learns nothing beyond the connection's
//! existence and the constant frame rate. AEAD
//! authentication also rejects any byte the network
//! mutates in transit.
//!
//! For a real deployment, swap the PSK handshake for a
//! proper key-exchange protocol (Noise XX, TLS 1.3, or
//! similar). The peaveil-specific wiring stays the same.
//!
//! Run with: cargo run --example encrypted

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use peaveil::{Connection, ConnectionSide, CoverStrategy, Handshake, Node, NodeConfig, Pea2Pea};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tracing_subscriber::EnvFilter;

const PSK: [u8; 32] = [0x42; 32];
const NONCE_LEN: usize = 32;
const CHUNK_NONCE_LEN: usize = 12;
const CHUNK_TAG_LEN: usize = 16;
const LEN_LEN: usize = 4;

/// A `pea2pea` `Handshake` that authenticates the peer
/// with a pre-shared key and wraps the TCP stream in
/// ChaCha20-Poly1305. See the module docs for the
/// protocol.
#[derive(Clone)]
struct PskHandshake {
    inner: Arc<peashape::Node>,
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

        // 1. Nonce exchange. The initiator writes first, the
        // responder reads first, so each side does one
        // write_all and one read_exact in opposite orders.
        // The two nonces plus the PSK feed HKDF below.
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
        // No shutdown here: the handshake is transparent to
        // the connection — the same TCP socket keeps carrying
        // peaveil frames after we return.

        // 2. Derive a session key. Sorting the two nonces
        // before mixing makes the derivation order-independent
        // — both sides arrive at the same key regardless of
        // which is "ours".
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

        // 3. Wrap the two halves and return the combined
        // stream to the connection.
        let wrapped = BiStream {
            read: DecStream::new(read, cipher.clone()),
            write: EncStream::new(write, cipher),
        };
        self.return_stream(&mut conn, wrapped);
        Ok(conn)
    }
}

// --- chunked AEAD stream wrap -----------------------------------------------
//
// Each direction carries length-prefixed AEAD chunks:
//   [u32 BE ciphertext_len] [12-byte nonce] [ciphertext] [16-byte Poly1305 tag]
// where `ciphertext_len` is the *plaintext* length plus the 16-byte tag.
// The nonce is generated randomly per chunk. Decryption failures
// (network corruption, wrong key, MITM) are surfaced as `io::Error`.

struct EncStream<W: AsyncWrite + Unpin> {
    inner: W,
    cipher: ChaCha20Poly1305,
    /// Bytes still to flush from a previous `poll_write` call:
    /// the (already-framed) length+nonce+ciphertext+tag of one
    /// AEAD chunk, draining across as many inner writes as
    /// necessary.
    pending: Option<(usize, BytesMut)>,
}

impl<W: AsyncWrite + Unpin> EncStream<W> {
    fn new(inner: W, cipher: ChaCha20Poly1305) -> Self {
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

        // Drain a pending chunk first; until it is fully on
        // the wire, the corresponding plaintext is "in
        // flight" and the caller's `buf.len()` cannot be
        // counted as written.
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

        // Build the framed chunk and drive it through the
        // inner stream in a single pass. For peaveil's
        // 256-byte frame the framed chunk is 288 bytes
        // (4 + 12 + 256 + 16), which fits in one TCP
        // segment; the loop only matters for hypothetical
        // short writes, and partial writes are stashed back
        // into `pending` so the next call resumes.
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

struct DecStream<R: AsyncRead + Unpin> {
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
    fn new(inner: R, cipher: ChaCha20Poly1305) -> Self {
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

struct BiStream<R, W> {
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

// --- demo -------------------------------------------------------------------

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║  peaveil — encrypted (PSK + ChaCha20-Poly1305) demo         ║");
    println!("╚═════════════════════════════════════════════════════════════╝");
    println!();
    println!("Two nodes share a 32-byte PSK, perform a 32-byte nonce");
    println!("exchange, derive a session key with HKDF-SHA256, and wrap");
    println!("the TCP stream in length-prefixed ChaCha20-Poly1305 chunks.");
    println!("A passive observer now sees only AEAD ciphertext + cover.\n");

    fn mk_node(name: &str) -> Result<Node, Box<dyn std::error::Error>> {
        Ok(Node::new(NodeConfig {
            name: Some(name.into()),
            listener_addr: Some("127.0.0.1:0".parse()?),
            cover: CoverStrategy::Constant {
                interval: Duration::from_millis(100),
            },
            ..Default::default()
        }))
    }

    let alice = mk_node("alice")?;
    let bob = mk_node("bob")?;

    // Register the PSK handshake on *both* nodes, *before*
    // spawn(). enable_handshake() must run while the peashape
    // node is quiescent (listener off, no in-flight
    // connections).
    for n in [&alice, &bob] {
        let hs = PskHandshake {
            inner: Arc::new(n.peashape().clone()),
        };
        hs.enable_handshake().await;
    }

    alice.spawn().await?;
    bob.spawn().await?;

    let alice_addr = alice.local_addr().await?.expect("alice bound");
    let bob_addr = bob.local_addr().await?.expect("bob bound");
    println!("alice bound on {alice_addr}");
    println!("bob   bound on {bob_addr}");

    // Seed the views and open the connections. The connect()
    // calls are what trigger the handshake on each side.
    alice.add_recent(bob_addr);
    bob.add_recent(alice_addr);
    alice.connect(bob_addr).await?;
    bob.connect(alice_addr).await?;
    for _ in 0..50 {
        if alice.connected_peers().contains(&bob_addr)
            && bob.connected_peers().contains(&alice_addr)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !alice.connected_peers().contains(&bob_addr) {
        eprintln!("alice did not connect to bob within the deadline");
        alice.shutdown().await;
        bob.shutdown().await;
        std::process::exit(1);
    }

    // The connection has been established, the handshake has
    // been performed on both sides, and the stream is wrapped.
    // From here on, every byte on the wire is AEAD ciphertext
    // (or peashape cover, which is also indistinguishable from
    // random). The peaveil explorer will gossip over it as
    // normal.
    let mut alice_events = alice.subscribe_events();
    let alice_events_task = tokio::spawn(async move {
        while let Ok(event) = alice_events.recv().await {
            match event {
                peaveil::DiscoveryEvent::SampleSent { to, count } => {
                    println!("alice -> {to}: sent sample ({count} entries, over AEAD)");
                }
                peaveil::DiscoveryEvent::SampleReceived { count, .. } => {
                    println!("alice <- ???: received sample ({count} entries, decrypted)");
                }
                peaveil::DiscoveryEvent::PeerDiscovered { addr, category } => {
                    println!("alice discovered {addr} as {category:?}");
                }
                _ => {}
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(3)).await;
    alice_events_task.abort();

    println!();
    println!("=== Alice's view (after the encrypted exchange) ===");
    print_view(&alice.view());
    println!();
    println!("=== Bob's view (after the encrypted exchange) ===");
    print_view(&bob.view());

    alice.shutdown().await;
    bob.shutdown().await;
    Ok(())
}

fn print_view(view: &peaveil::ViewSnapshot) {
    let total = view.total();
    if total == 0 {
        println!("  (empty — only self-entry, no other peers known)");
        return;
    }
    for p in &view.trusted {
        println!(
            "  [trusted] {}:{}  (seen {} times)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
        );
    }
    for p in &view.recent {
        println!(
            "  [recent]  {}:{}  (seen {} times)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
        );
    }
    for p in &view.random {
        println!(
            "  [random]  {}:{}  (seen {} times)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
        );
    }
    for p in &view.bootstrap {
        println!("  [boot]    {}:{}  (bootstrap)", p.addr.ip(), p.addr.port(),);
    }
}
