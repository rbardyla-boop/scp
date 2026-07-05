/// SCP relay wire protocol version.
///
/// Currently only V1 exists. V2 will be introduced when the relay layer
/// adds a unified framing header with BLAKE3-derived session authentication.
/// Negotiation: min(local, remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum WireVersion {
    V1 = 1,
}

impl WireVersion {
    /// Negotiate the wire version to use given local and remote capabilities.
    /// Uses the lower of the two — conservative compatibility.
    pub fn negotiate(local: Self, remote: Self) -> Self {
        if (local as u8) <= (remote as u8) {
            local
        } else {
            remote
        }
    }

    pub fn current() -> Self {
        Self::V1
    }
}
