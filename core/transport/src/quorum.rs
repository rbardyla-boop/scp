use blake3::Hasher;
use scp_vitality::VitalityState;

use crate::flash::{PublishedHandshakeKey, RecipientState};
use crate::state::StateProvider;

// ── ProviderObservation ──────────────────────────────────────────────────────

/// A single provider's observation of a state value, with a verifiable commitment.
///
/// The `commitment` field is a BLAKE3 hash over the canonical encoding of `value`,
/// allowing provider outputs to be compared without transmitting raw values.
pub struct ProviderObservation<T> {
    pub provider_id: [u8; 32],
    pub observed_at: u64,
    pub value: T,
    pub commitment: [u8; 32],
}

// ── QuorumResult ─────────────────────────────────────────────────────────────

/// The outcome of a multi-provider quorum query.
pub enum QuorumResult<T> {
    /// All relevant providers agreed; the resolved value is returned.
    Agree(T),
    /// Two providers returned conflicting commitments — hard equivocation.
    /// Only possible for Consensus-Relevant state (see STATE_SEMANTICS.md).
    Equivocation(EquivocationEvidence),
    /// No providers were queried, or all providers were filtered (e.g. all revoked).
    Unavailable,
}

// ── EquivocationEvidence ─────────────────────────────────────────────────────

/// Cryptographic evidence that two providers disagree on a Consensus-Relevant claim.
///
/// Both commitments are computed via `RecipientState::commitment()` — the same
/// protocol-stable hash used for audit proofs and zk-attestations.
pub struct EquivocationEvidence {
    pub ops_pub: [u8; 32],
    pub provider_a_id: [u8; 32],
    pub provider_b_id: [u8; 32],
    pub commitment_a: [u8; 32],
    pub commitment_b: [u8; 32],
}

// ── ProviderQuorum ───────────────────────────────────────────────────────────

/// Multi-provider dispatcher that applies the correct resolution rule per semantic class.
///
/// See STATE_SEMANTICS.md for the class taxonomy and resolution contract.
/// Use the `_quorum` methods for full resolution including equivocation evidence;
/// use the `StateProvider` impl as a drop-in where a single provider is expected.
pub struct ProviderQuorum<P> {
    providers: Vec<([u8; 32], P)>,
}

impl<P: StateProvider> ProviderQuorum<P> {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn from_providers(providers: Vec<([u8; 32], P)>) -> Self {
        Self { providers }
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn add(&mut self, provider_id: [u8; 32], provider: P) {
        self.providers.push((provider_id, provider));
    }

    // ── Monotonic: is_revoked ────────────────────────────────────────────────
    //
    // Resolution: any() wins. A single revocation claim from any provider is
    // sufficient grounds to deny transport. A provider that has not yet seen the
    // revocation (returning false while others return true) is lagging, not
    // equivocating — it will converge. No Equivocation surface here.

    /// Quorum query for revocation status (Monotonic).
    ///
    /// Returns `Agree(true)` if any provider sees the key as revoked.
    /// Returns `Agree(false)` if all providers see the key as valid.
    /// Returns `Unavailable` if the quorum is empty.
    pub fn is_revoked_quorum(&self, ops_pub: &[u8; 32]) -> QuorumResult<bool> {
        if self.providers.is_empty() {
            return QuorumResult::Unavailable;
        }
        let any_revoked = self.providers.iter().any(|(_, p)| p.is_revoked(ops_pub));
        QuorumResult::Agree(any_revoked)
    }

    // ── Soft-State: get_handshake_ephemeral ──────────────────────────────────
    //
    // Resolution: latest_valid(now). The most recently expiring valid ephemeral
    // across all providers wins. A provider returning None does not override a
    // provider returning Some — absence is weak. Divergence is replication lag.
    // No Equivocation surface here.

    /// Quorum query for handshake ephemeral (Soft-State).
    ///
    /// Returns `Agree(Some(key))` with the latest-expiring valid ephemeral across
    /// all providers. Returns `Agree(None)` if all providers have no valid ephemeral.
    /// Returns `Unavailable` if the quorum is empty.
    pub fn get_handshake_ephemeral_quorum(
        &self,
        ops_pub: &[u8; 32],
        now: u64,
    ) -> QuorumResult<Option<PublishedHandshakeKey>> {
        if self.providers.is_empty() {
            return QuorumResult::Unavailable;
        }
        let best = self
            .providers
            .iter()
            .filter_map(|(_, p)| p.get_handshake_ephemeral(ops_pub, now))
            .max_by_key(|eph| eph.expires_at);
        QuorumResult::Agree(best)
    }

    // ── Consensus-Relevant: get_commitment ───────────────────────────────────
    //
    // Resolution: all_agree(). All non-revoked providers must return the same
    // state commitment. Any disagreement is hard equivocation — EquivocationEvidence
    // is returned with the diverging provider IDs and commitments.
    //
    // Revoked providers are filtered before comparison: a revoked provider has no
    // valid state to commit to. If all providers are revoked, returns Unavailable.
    //
    // Commitment computation: build a partial RecipientState from each provider's
    // view (using VitalityState::Active + empty routing_hints, matching retrieve_state)
    // and call .commitment() — reusing the protocol-stable hash.

    /// Quorum query for state commitment (Consensus-Relevant).
    ///
    /// Returns `Agree(commitment)` if all non-revoked providers agree.
    /// Returns `Equivocation(evidence)` if any two non-revoked providers disagree.
    /// Returns `Unavailable` if the quorum is empty or all providers are revoked.
    pub fn get_commitment_quorum(&self, ops_pub: &[u8; 32]) -> QuorumResult<[u8; 32]> {
        if self.providers.is_empty() {
            return QuorumResult::Unavailable;
        }

        let now = now_secs();

        // Collect (provider_id, commitment) for non-revoked providers.
        let observations: Vec<([u8; 32], [u8; 32])> = self
            .providers
            .iter()
            .filter(|(_, p)| !p.is_revoked(ops_pub))
            .map(|(id, p)| {
                let state = RecipientState {
                    ops_pub: *ops_pub,
                    vitality: VitalityState::Active,
                    routing_hints: vec![],
                    handshake_ephemeral: p.get_handshake_ephemeral(ops_pub, now),
                };
                (*id, state.commitment())
            })
            .collect();

        if observations.is_empty() {
            return QuorumResult::Unavailable;
        }

        let (first_id, first_commitment) = observations[0];
        for (id, commitment) in &observations[1..] {
            if *commitment != first_commitment {
                return QuorumResult::Equivocation(EquivocationEvidence {
                    ops_pub: *ops_pub,
                    provider_a_id: first_id,
                    provider_b_id: *id,
                    commitment_a: first_commitment,
                    commitment_b: *commitment,
                });
            }
        }

        QuorumResult::Agree(first_commitment)
    }
}

// ── StateProvider drop-in ────────────────────────────────────────────────────
//
// ProviderQuorum<P> implements StateProvider so it can replace a single provider
// anywhere — FlashSession::retrieve_state, tests, or any future transport caller.
// The resolution rules applied here are the safe conservative defaults:
//   is_revoked:              monotonic any() — never under-blocks
//   get_handshake_ephemeral: soft-state latest_valid — never under-serves

impl<P: StateProvider> StateProvider for ProviderQuorum<P> {
    fn is_revoked(&self, ops_pub: &[u8; 32]) -> bool {
        self.providers.iter().any(|(_, p)| p.is_revoked(ops_pub))
    }

    fn get_handshake_ephemeral(
        &self,
        ops_pub: &[u8; 32],
        now: u64,
    ) -> Option<PublishedHandshakeKey> {
        self.providers
            .iter()
            .filter_map(|(_, p)| p.get_handshake_ephemeral(ops_pub, now))
            .max_by_key(|eph| eph.expires_at)
    }
}

impl<P: StateProvider> Default for ProviderQuorum<P> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Commitment helpers ───────────────────────────────────────────────────────

/// Domain-separated BLAKE3 commitment over a revocation claim.
///
/// Separate from `RecipientState::commitment()` — revocation is Monotonic, not
/// Consensus-Relevant. Domain separation prevents commitment cross-class confusion.
///
/// Encoding: BLAKE3("scp:revocation:v0:" || ops_pub(32) || [is_revoked as u8])
pub fn revocation_commitment(ops_pub: &[u8; 32], is_revoked: bool) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"scp:revocation:v0:");
    h.update(ops_pub);
    h.update(&[is_revoked as u8]);
    *h.finalize().as_bytes()
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
