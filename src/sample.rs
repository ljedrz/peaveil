//! Wire format for a `peaveil` peer sample.
//!
//! A peer sample is the unit of exchange in the
//! `peaveil` discovery protocol: a list of `(address, age)`
//! pairs, sent from one node to another. The full overlay
//! behaviour of `peaveil` is built by repeatedly shipping these
//! objects back and forth.
//!
//! # Frame layout
//!
//! A `peaveil` frame rides on top of [`peashape`], so the
//! first [`peashape::ID_SIZE`] bytes of every on-the-wire frame
//! are the peashape message identifier. The peaveil payload
//! follows it:
//!
//! ```text
//! +--------+---------+---------+-----------+---------------+
//! |   ID   |  magic  | version |  count N  | N x PeerEntry |
//! | (32 B) |  (1 B)  |  (1 B)  |   (1 B)   |  (8 or 20 B)  |
//! +--------+---------+---------+-----------+---------------+
//! ```
//!
//! `PeerEntry` is:
//!
//! ```text
//! +--------+-------------+--------+----------+
//! | family |  address    | port   |  age     |
//! | (1 B)  | (4 or 16 B) | (2 B)  |  (4 B)   |
//! +--------+-------------+--------+----------+
//! ```
//!
//! - `family` is `0x04` for IPv4 (4 address bytes follow) or
//!   `0x06` for IPv6 (16 address bytes follow).
//! - `port` is a 2-byte big-endian unsigned integer.
//! - `age` is a 4-byte big-endian unsigned integer, the number
//!   of seconds (saturated to `u32::MAX`) since the sender last
//!   *heard from* this peer.
//!
//! # Magic and version
//!
//! The first byte of the peaveil payload is a fixed magic
//! (`PEAVEIL_MAGIC`). The second byte is the protocol version
//! (`PEAVEIL_VERSION`). The magic is the cheapest possible
//! filter for cover frames: random bytes match it with
//! probability `1/256` per frame, which is vanishingly small
//! over any realistic observation window.
//!
//! # Privacy of the wire format
//!
//! The contents of a sample are *plaintext*: an observer who
//! can break the link encryption (or is on-path) can read the
//! full list of peers a node has been talking to. That is a
//! metadata leak by design, and `peaveil` does not attempt to
//! hide it on its own. End-to-end confidentiality of the
//! sample is the application's responsibility; layer it via
//! a `pea2pea` `Handshake` (e.g. Noise / TLS) or by encrypting
//! the payload before it is submitted to `peashape`. The
//! constant size, constant timing, and per-tick cover that
//! `peashape` already provides still defeat the
//! "is this node exchanging samples right now?" question
//! regardless.
//!
//! [`peashape`]: peashape

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, BytesMut};

/// On-the-wire magic that prefixes every `peaveil` payload.
///
/// The value is `0x50`, the ASCII code for `'P'` (for
/// `peaveil`). Cover frames (random bytes) match it with
/// probability `1/256` per frame.
pub const PEAVEIL_MAGIC: u8 = 0x50;

/// Current wire-protocol version.
///
/// Bumped only on backwards-incompatible changes to the
/// encoding.
pub const PEAVEIL_VERSION: u8 = 0x01;

/// Size, in bytes, of an IPv4 peer entry.
pub const IPV4_ENTRY_SIZE: usize = 1 + 4 + 2 + 4;
/// Size, in bytes, of an IPv6 peer entry.
pub const IPV6_ENTRY_SIZE: usize = 1 + 16 + 2 + 4;
/// Size, in bytes, of the sample header (magic + version + count).
pub const SAMPLE_HEADER_SIZE: usize = 3;

/// A single peer in a [`PeerSample`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerEntry {
    /// The peer's socket address.
    pub addr: SocketAddr,
    /// Seconds since the sender last heard from this peer.
    /// Saturated at `u32::MAX`. An age of zero just means
    /// "heard from right now"; the sender includes its own
    /// address with age zero so the receiver learns about it,
    /// but the wire format carries no sender flag, so a
    /// zero-age entry is *not* distinguishable from any other
    /// freshly-seen peer.
    pub age_secs: u32,
}

impl PeerEntry {
    fn encoded_size(&self) -> usize {
        match self.addr.ip() {
            IpAddr::V4(_) => IPV4_ENTRY_SIZE,
            IpAddr::V6(_) => IPV6_ENTRY_SIZE,
        }
    }
}

/// A list of peers to be exchanged between two nodes.
///
/// `peaveil` builds a `PeerSample` by drawing a uniformly
/// random subset of its [`View`](crate::ViewSnapshot) and ships
/// it to a randomly-chosen peer. The recipient merges the
/// received entries into its own view, deduplicating by
/// `SocketAddr`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSample {
    entries: Vec<PeerEntry>,
}

impl PeerSample {
    /// Returns an empty sample. Useful for "ping" exchanges
    /// that test liveness without contributing new peers.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Builds a sample from a list of entries. The entries are
    /// not validated; the caller is expected to de-duplicate
    /// and bound the size before calling.
    pub fn from_entries(entries: Vec<PeerEntry>) -> Self {
        Self { entries }
    }

    /// Returns the entries of this sample.
    pub fn entries(&self) -> &[PeerEntry] {
        &self.entries
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the sample has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the encoded size of this sample, in bytes, when
    /// serialized as a `peaveil` payload.
    pub fn encoded_size(&self) -> usize {
        SAMPLE_HEADER_SIZE + self.entries.iter().map(PeerEntry::encoded_size).sum::<usize>()
    }

    /// Maximum number of entries a single sample can carry.
    /// The wire format uses a 1-byte `count` field, so a
    /// `PeerSample` can hold at most 255 entries. In practice
    /// the configured `sample_size` (default 8) is well under
    /// this; encoding more than 255 entries is a
    /// programmer error.
    pub const MAX_ENTRIES: usize = u8::MAX as usize;

    /// Encodes this sample into a freshly-allocated
    /// `BytesMut`. The returned buffer is exactly
    /// `self.encoded_size()` bytes long.
    ///
    /// # Panics
    ///
    /// Panics if `self.len() > Self::MAX_ENTRIES`.
    pub fn encode(&self) -> BytesMut {
        assert!(
            self.entries.len() <= Self::MAX_ENTRIES,
            "peer sample cannot carry more than {} entries (got {})",
            Self::MAX_ENTRIES,
            self.entries.len(),
        );
        let mut out = BytesMut::with_capacity(self.encoded_size());
        out.put_u8(PEAVEIL_MAGIC);
        out.put_u8(PEAVEIL_VERSION);
        out.put_u8(self.entries.len() as u8);
        for entry in &self.entries {
            encode_entry(&mut out, entry);
        }
        debug_assert_eq!(out.len(), self.encoded_size());
        out
    }

    /// Decodes a `peaveil` payload. Returns `Err(_)` if the
    /// buffer is too short, has a wrong magic, has a wrong
    /// version, or has a truncated trailing entry. Trailing
    /// bytes after the last declared entry are *ignored*,
    /// since the on-the-wire format pads the sample with
    /// random bytes to fit the peashape frame size.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < SAMPLE_HEADER_SIZE {
            return Err(DecodeError::Truncated);
        }
        if buf[0] != PEAVEIL_MAGIC {
            return Err(DecodeError::BadMagic(buf[0]));
        }
        if buf[1] != PEAVEIL_VERSION {
            return Err(DecodeError::BadVersion(buf[1]));
        }
        let count = buf[2] as usize;
        let mut entries = Vec::with_capacity(count);
        let mut cursor = SAMPLE_HEADER_SIZE;
        for _ in 0..count {
            let family = *buf.get(cursor).ok_or(DecodeError::Truncated)?;
            let (entry_size, entry) = match family {
                0x04 => {
                    if buf.len() < cursor + IPV4_ENTRY_SIZE {
                        return Err(DecodeError::Truncated);
                    }
                    let ip = Ipv4Addr::new(
                        buf[cursor + 1],
                        buf[cursor + 2],
                        buf[cursor + 3],
                        buf[cursor + 4],
                    );
                    let port = u16::from_be_bytes([buf[cursor + 5], buf[cursor + 6]]);
                    let age = u32::from_be_bytes([
                        buf[cursor + 7],
                        buf[cursor + 8],
                        buf[cursor + 9],
                        buf[cursor + 10],
                    ]);
                    (
                        IPV4_ENTRY_SIZE,
                        PeerEntry {
                            addr: SocketAddr::new(IpAddr::V4(ip), port),
                            age_secs: age,
                        },
                    )
                }
                0x06 => {
                    if buf.len() < cursor + IPV6_ENTRY_SIZE {
                        return Err(DecodeError::Truncated);
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[cursor + 1..cursor + 17]);
                    let port = u16::from_be_bytes([buf[cursor + 17], buf[cursor + 18]]);
                    let age = u32::from_be_bytes([
                        buf[cursor + 19],
                        buf[cursor + 20],
                        buf[cursor + 21],
                        buf[cursor + 22],
                    ]);
                    (
                        IPV6_ENTRY_SIZE,
                        PeerEntry {
                            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                            age_secs: age,
                        },
                    )
                }
                other => return Err(DecodeError::BadFamily(other)),
            };
            cursor += entry_size;
            entries.push(entry);
        }
        // Trailing bytes (the random padding added by the
        // sender to fit the peashape frame) are silently
        // ignored: the protocol is fully self-describing
        // thanks to the count field.
        Ok(Self { entries })
    }
}

fn encode_entry(out: &mut BytesMut, entry: &PeerEntry) {
    match entry.addr.ip() {
        IpAddr::V4(v4) => {
            out.put_u8(0x04);
            out.put_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.put_u8(0x06);
            out.put_slice(&v6.octets());
        }
    }
    out.put_u16(entry.addr.port());
    out.put_u32(entry.age_secs);
}

/// All the ways a `peaveil` payload can fail to decode.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The buffer is too short to contain the declared entries.
    Truncated,
    /// The buffer's first byte is not the `peaveil` magic.
    /// The received byte is reported for diagnostics.
    BadMagic(u8),
    /// The buffer's second byte is not the `peaveil` version.
    /// The received byte is reported for diagnostics.
    BadVersion(u8),
    /// An entry's family byte is neither `0x04` nor `0x06`.
    BadFamily(u8),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("truncated buffer"),
            DecodeError::BadMagic(b) => write!(f, "bad magic 0x{b:02x}"),
            DecodeError::BadVersion(b) => write!(f, "bad version 0x{b:02x}"),
            DecodeError::BadFamily(b) => write!(f, "bad address family 0x{b:02x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PeerSample {
        PeerSample::from_entries(vec![
            PeerEntry {
                addr: "10.0.0.1:9000".parse().unwrap(),
                age_secs: 5,
            },
            PeerEntry {
                addr: "[2001:db8::1]:9000".parse().unwrap(),
                age_secs: 12,
            },
            PeerEntry {
                addr: "10.0.0.2:9000".parse().unwrap(),
                age_secs: 0,
            },
        ])
    }

    #[test]
    fn roundtrip() {
        let s = sample();
        let bytes = s.encode();
        let decoded = PeerSample::decode(&bytes).expect("decode");
        assert_eq!(s, decoded);
    }

    #[test]
    fn roundtrip_empty() {
        let s = PeerSample::empty();
        let bytes = s.encode();
        assert_eq!(bytes.len(), SAMPLE_HEADER_SIZE);
        let decoded = PeerSample::decode(&bytes).expect("decode");
        assert_eq!(s, decoded);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = sample().encode();
        bytes[0] = 0xAB;
        assert!(matches!(
            PeerSample::decode(&bytes),
            Err(DecodeError::BadMagic(0xAB))
        ));
    }

    #[test]
    fn bad_version_rejected() {
        let mut bytes = sample().encode();
        bytes[1] = 0x99;
        assert!(matches!(
            PeerSample::decode(&bytes),
            Err(DecodeError::BadVersion(0x99))
        ));
    }

    #[test]
    fn truncated_rejected() {
        let bytes = sample().encode();
        let truncated = &bytes[..bytes.len() - 3];
        assert!(matches!(PeerSample::decode(truncated), Err(DecodeError::Truncated)));
    }

    #[test]
    fn trailing_padding_ignored() {
        // Trailing bytes are random padding added by the
        // sender to fit the peashape frame size; the
        // decoder ignores them rather than rejecting.
        let mut bytes = sample().encode();
        for _ in 0..5 {
            bytes.put_u8(0x42);
        }
        let decoded = PeerSample::decode(&bytes).expect("decode");
        assert_eq!(decoded, sample());
    }

    #[test]
    #[should_panic(expected = "cannot carry more than")]
    fn encode_panics_on_overflow() {
        let entries: Vec<PeerEntry> = (0..PeerSample::MAX_ENTRIES + 1)
            .map(|i| PeerEntry {
                addr: format!("10.0.0.{}:80", i % 256).parse().unwrap(),
                age_secs: 0,
            })
            .collect();
        let sample = PeerSample::from_entries(entries);
        sample.encode();
    }

    #[test]
    fn max_ipv4_per_frame_is_at_least_20() {
        // The default `frame_size` is 256. The default sample
        // size is 8. A 256-byte frame comfortably holds
        // 20 IPv4 peers per sample (and 8 IPv6 peers). That
        // is well above the default `sample_size = 8`, so
        // the codec remains useful with the default
        // configuration.
        let payload = peashape::ID_SIZE;
        let frame = 256;
        let available = frame - payload - SAMPLE_HEADER_SIZE;
        let max_per_frame = available / IPV4_ENTRY_SIZE;
        assert!(
            max_per_frame >= 20,
            "a 256-byte frame should fit at least 20 IPv4 peers; fits {max_per_frame}",
        );
    }
}
