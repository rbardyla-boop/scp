/// Sliding bitmap replay window for FreshnessNonce.
///
/// Tracks 64 nonce values centered on the highest accepted value (`max_seen`).
/// A nonce is accepted if:
///   - It is novel (not yet in the window), AND
///   - It is not older than max_seen − 63 (not stale).
///
/// Advancing the window: any nonce > max_seen slides the bitmap forward and
/// accepts the nonce. Nonces outside the bottom of the window are rejected
/// without updating state.
///
/// This is transport-local and ephemeral. Never persist, export, or share a
/// ReplayWindow across relay hops — that would create distributed memory and
/// relay-side behavioral history, both of which undermine SCP doctrine.
pub struct ReplayWindow {
    /// Highest nonce accepted so far.
    max_seen: u64,
    /// Bitmap of the 64-slot window. Bit i represents nonce (max_seen − i).
    /// Bit 0 always corresponds to max_seen itself.
    bitmap: u64,
    /// False until the first nonce is accepted; avoids max_seen = 0 ambiguity.
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { max_seen: 0, bitmap: 0, initialized: false }
    }

    /// Validate and record `nonce`. Returns `true` if accepted, `false` if
    /// duplicate or outside the window (replay or stale).
    pub fn check_and_insert(&mut self, nonce: u64) -> bool {
        if !self.initialized {
            self.max_seen = nonce;
            self.bitmap = 1u64;
            self.initialized = true;
            return true;
        }

        if nonce > self.max_seen {
            let shift = nonce - self.max_seen;
            // Shift window forward; clear vacated bits, mark current nonce.
            self.bitmap = if shift >= 64 { 1u64 } else { (self.bitmap << shift) | 1u64 };
            self.max_seen = nonce;
            true
        } else {
            let offset = self.max_seen - nonce;
            if offset >= 64 {
                return false; // too old — outside window
            }
            let mask = 1u64 << offset;
            if self.bitmap & mask != 0 {
                false // replay — already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}
