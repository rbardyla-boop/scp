use crate::flash::PublishedHandshakeKey;
use scp_ledger_substrate::SubstrateLedger;

/// Transport-layer interface to the sovereign state layer.
///
/// Sync methods: the in-memory SubstrateLedger needs no async I/O.
/// Phase 9: if a real RPC client is added, revisit whether the trait
/// needs async fn or whether async wrapping stays at retrieve_state().
pub trait StateProvider {
    fn is_revoked(&self, ops_pub: &[u8; 32]) -> bool;
    fn get_handshake_ephemeral(
        &self,
        ops_pub: &[u8; 32],
        now: u64,
    ) -> Option<PublishedHandshakeKey>;
}

/// Stub — always non-revoked, no published ephemeral.
/// Use in tests that only exercise the v1 (OsRng seed) session path.
pub struct StubStateProvider;

impl StateProvider for StubStateProvider {
    fn is_revoked(&self, _: &[u8; 32]) -> bool {
        false
    }
    fn get_handshake_ephemeral(&self, _: &[u8; 32], _: u64) -> Option<PublishedHandshakeKey> {
        None
    }
}

/// Real implementation backed by the in-memory Substrate ledger.
///
/// Converts HandshakeEphemeral.sig (Vec<u8>) → PublishedHandshakeKey.sig ([u8; 64]).
/// The ledger validates sig length on publish, so try_into().ok() silently drops
/// any malformed entry — defense-in-depth; should never trigger in practice.
impl StateProvider for SubstrateLedger {
    fn is_revoked(&self, ops_pub: &[u8; 32]) -> bool {
        SubstrateLedger::is_revoked(self, ops_pub)
    }

    fn get_handshake_ephemeral(
        &self,
        ops_pub: &[u8; 32],
        now: u64,
    ) -> Option<PublishedHandshakeKey> {
        let eph = SubstrateLedger::get_handshake_ephemeral(self, ops_pub, now)?;
        let sig: [u8; 64] = eph.sig[..].try_into().ok()?;
        Some(PublishedHandshakeKey {
            pub_key: eph.pub_key,
            sig,
            expires_at: eph.expires_at,
        })
    }
}
