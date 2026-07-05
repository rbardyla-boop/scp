//! Real message-delivery routing over `ProviderPool`'s liveness engine (Option 2).
//!
//! See `docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md` for the
//! full design and the ADR verdict this crate implements
//! (`B — OPTION_2_ROUTING_SEAM_AUTHORIZED`, admissible-surface sub-decision).
//!
//! `DeliveryEndpoint` is deliberately NOT `StateProvider`-shaped: a relay stores
//! and forwards opaque bursts, it holds no revocation/handshake-ephemeral/
//! commitment state, and must never be asked a state-consistency question.
//! `DeliveryPool` is built on `ProviderPool`'s StateProvider-free
//! `sample_selected_with_receipts()` / `record_admissible_*()` surface — the
//! admissible (receipt-bound) surface, never the raw one, per the ADR's
//! sub-decision (blunts the steering attack: an adversary who can induce
//! failures against a relay could otherwise steer real traffic away from it).

use scp_transport::harness::DevMailboxId;

/// A real message-delivery endpoint the pool may select among.
///
/// NOT a `StateProvider`. Delivery outcomes are liveness signals, not state
/// claims — they carry no equivocation semantics.
pub trait DeliveryEndpoint {
    /// Stable pool key for this endpoint. MUST be a random per-endpoint tag
    /// assigned out-of-band by the operator — NOT the network address, NOT
    /// any identity key (see design §3.2: keeps pool internals address-free
    /// and keeps relay selection from becoming a stable correlation key).
    fn endpoint_id(&self) -> [u8; 32];

    /// Attempt to store one CBOR-serialized `DevHarnessBurst` to a mailbox.
    /// Mirrors `cli/endpoint`'s `relay_store()`: one `TcpStream::connect`,
    /// `[0x01][32 token][4 len LE][N bytes]`, await `[0x00]` ack.
    fn attempt_store(
        &self,
        mailbox: &DevMailboxId,
        burst_cbor: &[u8],
    ) -> impl std::future::Future<Output = Result<(), DeliveryError>> + Send;

    /// Attempt to drain a mailbox. Mirrors `relay_poll()`.
    fn attempt_poll(
        &self,
        mailbox: &DevMailboxId,
    ) -> impl std::future::Future<Output = Result<Vec<Vec<u8>>, DeliveryError>> + Send;
}

/// Failure taxonomy that becomes the liveness signal, derived from the real
/// `io::Error` paths in `relay_store()`/`relay_poll()`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DeliveryError {
    #[error("connection refused")]
    ConnectionRefused,
    #[error("operation timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// One selected route for a single delivery attempt, paired with the receipt
/// that MUST be presented back to record its outcome. There is no bare-id
/// outcome-recording path — callers cannot record an outcome without a receipt.
pub struct DeliveryRoute<D> {
    pub endpoint: D,
    pub receipt: scp_provider_pool::SelectionReceipt,
}

/// A real relay endpoint reached over TCP.
#[derive(Clone)]
pub struct RelayEndpoint {
    endpoint_id: [u8; 32],
    addr: String,
}

impl RelayEndpoint {
    pub fn new(endpoint_id: [u8; 32], addr: impl Into<String>) -> Self {
        Self {
            endpoint_id,
            addr: addr.into(),
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

/// Maps a real `io::Error` from a TCP attempt to the `DeliveryError` taxonomy
/// that becomes the liveness signal fed to `DeliveryPool`.
fn map_io_error(e: std::io::Error) -> DeliveryError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused => DeliveryError::ConnectionRefused,
        ErrorKind::TimedOut => DeliveryError::Timeout,
        _ => DeliveryError::Protocol(e.to_string()),
    }
}

impl DeliveryEndpoint for RelayEndpoint {
    fn endpoint_id(&self) -> [u8; 32] {
        self.endpoint_id
    }

    async fn attempt_store(
        &self,
        mailbox: &DevMailboxId,
        burst_cbor: &[u8],
    ) -> Result<(), DeliveryError> {
        with_io_timeout(self.attempt_store_inner(mailbox, burst_cbor)).await
    }

    async fn attempt_poll(&self, mailbox: &DevMailboxId) -> Result<Vec<Vec<u8>>, DeliveryError> {
        with_io_timeout(self.attempt_poll_inner(mailbox)).await
    }
}

impl RelayEndpoint {
    async fn attempt_store_inner(
        &self,
        mailbox: &DevMailboxId,
        burst_cbor: &[u8],
    ) -> Result<(), DeliveryError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Wire framing ported verbatim from cli/endpoint/src/main.rs relay_store():
        // [0x01][32 token][4 len LE][N bytes] -> await [0x00] ack.
        let mut stream = TcpStream::connect(&self.addr).await.map_err(map_io_error)?;
        stream.write_all(&[0x01]).await.map_err(map_io_error)?;
        stream.write_all(&mailbox.0).await.map_err(map_io_error)?;
        let len = burst_cbor.len() as u32;
        stream
            .write_all(&len.to_le_bytes())
            .await
            .map_err(map_io_error)?;
        stream.write_all(burst_cbor).await.map_err(map_io_error)?;

        let mut ack = [0u8; 1];
        stream.read_exact(&mut ack).await.map_err(map_io_error)?;
        if ack[0] != 0x00 {
            return Err(DeliveryError::Protocol(
                "relay returned unexpected ack byte".into(),
            ));
        }
        Ok(())
    }

    async fn attempt_poll_inner(
        &self,
        mailbox: &DevMailboxId,
    ) -> Result<Vec<Vec<u8>>, DeliveryError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Wire framing ported verbatim from cli/endpoint/src/main.rs relay_poll():
        // [0x02][32 token] -> [4 count LE][for each: [4 len LE][N bytes]].
        // A relay is untrusted (blind by design, but not necessarily honest about
        // these header fields) — count and per-burst len are capped before any
        // allocation, mirroring the reference relay daemon's own MAX_BURST_BYTES.
        let mut stream = TcpStream::connect(&self.addr).await.map_err(map_io_error)?;
        stream.write_all(&[0x02]).await.map_err(map_io_error)?;
        stream.write_all(&mailbox.0).await.map_err(map_io_error)?;

        let mut count_buf = [0u8; 4];
        stream
            .read_exact(&mut count_buf)
            .await
            .map_err(map_io_error)?;
        let count = u32::from_le_bytes(count_buf) as usize;
        if count > MAX_BURSTS_PER_POLL {
            return Err(DeliveryError::Protocol(format!(
                "relay reported {count} bursts, exceeding the {MAX_BURSTS_PER_POLL} sanity bound"
            )));
        }

        let mut bursts = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(map_io_error)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_BURST_BYTES {
                return Err(DeliveryError::Protocol(format!(
                    "relay reported a {len}-byte burst, exceeding the {MAX_BURST_BYTES}-byte bound"
                )));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.map_err(map_io_error)?;
            bursts.push(buf);
        }
        Ok(bursts)
    }
}

/// Mirrors `relay/daemon/src/main.rs`'s own store-side bound — a poll response
/// claiming a larger single burst than the relay would ever have accepted on
/// store is either a bug or a hostile custom relay, either way not honored.
const MAX_BURST_BYTES: usize = 1_048_576;
/// Sanity bound on the number of bursts a single poll may claim to return —
/// prevents a hostile relay from forcing an unbounded `Vec::with_capacity`.
const MAX_BURSTS_PER_POLL: usize = 100_000;
/// Hard timeout for one store/poll attempt against one relay. A relay that
/// accepts a connection and then never responds must not stall the whole
/// failover attempt (or the other relays queued after it) indefinitely.
const RELAY_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn with_io_timeout<T>(
    fut: impl std::future::Future<Output = Result<T, DeliveryError>>,
) -> Result<T, DeliveryError> {
    match tokio::time::timeout(RELAY_IO_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(DeliveryError::Timeout),
    }
}

/// The audited routing seam: `ProviderPool` liveness may gate relay
/// *selection only*, exclusively through this type, per ADR verdict
/// `B — OPTION_2_ROUTING_SEAM_AUTHORIZED`
/// (`docs/architecture/PROVIDERPOOL_MULTIRELAY_ARCHITECTURE_DESIGN.md` §4).
///
/// Built on the admissible surface only — every outcome must carry a
/// `SelectionReceipt`. Deliberately does NOT expose `sample()`,
/// `sample_with_receipts()` (the `ProviderQuorum` forms), `get_commitment_quorum()`,
/// or any bare-id `record_response()`/`record_failure()` path. A delivery
/// endpoint must never reach a state-consistency quorum surface, and every
/// outcome must carry a receipt — enforced by this API's shape, not by
/// caller discipline.
///
/// ## Known limitation: unresolved routes permanently consume receipt capacity
///
/// A `SelectionReceipt` from `select_route()` is only reclaimed by presenting
/// it to `record_delivery_success()`/`record_delivery_failure()`. There is no
/// automatic expiry — a caller that selects a route and never resolves it
/// (drops it, panics before recording, or a hung `attempt_store`/`attempt_poll`
/// that the caller gives up on without recording) permanently burns one unit
/// of `max_outstanding_receipts`. This crate does not currently expose a
/// reclaim path (the pool's own reclaim, `do_rotate()`, also churns the
/// active/dormant provider sets as a side effect, which would change routing
/// behavior — not an acceptable trade merely to free capacity).
///
/// This is an accepted limitation for the current dev-harness usage: each
/// `scp-cli send`/`receive` invocation constructs a **fresh** `DeliveryPool`
/// that is discarded at process exit, so exhaustion is bounded to one
/// invocation's own relay-attempt count, not accumulated across a long-running
/// process. Callers MUST record an outcome (success or failure) for every
/// route `select_route()` returns — this is a caller obligation this API does
/// not enforce. A future long-running (daemon-style) consumer of this crate
/// would need a real reclaim mechanism (e.g. a TTL on outstanding receipts)
/// before reuse beyond a single short-lived process.
pub struct DeliveryPool<D: DeliveryEndpoint + Clone> {
    inner: scp_provider_pool::ProviderPool<D>,
}

impl<D: DeliveryEndpoint + Clone> DeliveryPool<D> {
    pub fn new(
        strategy: scp_provider_pool::SamplingStrategy,
        max_outstanding_receipts: usize,
    ) -> Self {
        Self {
            inner: scp_provider_pool::ProviderPool::new(strategy)
                .with_admissible_tracking(max_outstanding_receipts),
        }
    }

    pub fn with_liveness(mut self, max_failures: u32, max_silence_secs: u64) -> Self {
        self.inner = self.inner.with_liveness(max_failures, max_silence_secs);
        self
    }

    pub fn add(&mut self, endpoint: D) {
        let id = endpoint.endpoint_id();
        self.inner.add(id, endpoint);
    }

    /// Ordered, receipt-bound failover candidate list for ONE delivery attempt.
    /// Live endpoints only; order/multiplicity from the configured
    /// `SamplingStrategy`. Selection is a function of liveness + the caller's
    /// `rng` only — this method takes no mailbox/recipient argument, so
    /// selection cannot be keyed to either (design §3.2 anti-correlation
    /// invariant).
    pub fn select_route(
        &mut self,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<Vec<DeliveryRoute<D>>, scp_provider_pool::AdmissibilityError> {
        let (selected, receipts) = self.inner.sample_selected_with_receipts(rng)?;
        Ok(selected
            .into_iter()
            .zip(receipts)
            .map(|((_, endpoint), receipt)| DeliveryRoute { endpoint, receipt })
            .collect())
    }

    /// Records a successful delivery outcome.
    ///
    /// Requires a valid, at-most-once-bound `SelectionReceipt` from a prior
    /// `select_route()` call — this is what prevents an outcome from being
    /// recorded for an endpoint that was never actually selected/attempted
    /// (the anti-tampering property the ADR's admissible-surface mandate is
    /// about). Once validated, this ALSO drives the pool's raw liveness
    /// counter for the identical `receipt.provider_id()` — this is required
    /// for routing to actually respond to liveness (`record_admissible_*()`
    /// alone is documented as telemetry-only and does not feed `is_live()`;
    /// see design doc §1.4 addendum). The raw update is gated behind the
    /// receipt validation, so it cannot be triggered by a bare id — only by
    /// presenting a receipt this same pool issued for this same endpoint.
    pub fn record_delivery_success(
        &mut self,
        receipt: &scp_provider_pool::SelectionReceipt,
    ) -> Result<(), scp_provider_pool::AdmissibilityError> {
        self.inner.record_admissible_response(receipt)?;
        self.inner.record_response(receipt.provider_id());
        Ok(())
    }

    /// Records a failed delivery outcome. See `record_delivery_success()` for
    /// why this also drives the raw liveness counter after receipt validation.
    pub fn record_delivery_failure(
        &mut self,
        receipt: &scp_provider_pool::SelectionReceipt,
    ) -> Result<(), scp_provider_pool::AdmissibilityError> {
        self.inner.record_admissible_failure(receipt)?;
        self.inner.record_failure(receipt.provider_id());
        Ok(())
    }

    pub fn telemetry(&self) -> scp_provider_pool::OperationalTelemetrySnapshot {
        self.inner.operational_telemetry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::{Arc, Mutex};

    fn seeded() -> StdRng {
        StdRng::seed_from_u64(0)
    }

    #[derive(Clone)]
    struct MockEndpoint {
        endpoint_id: [u8; 32],
        // Scripted outcomes consumed in order; None means "not yet used".
        calls: Arc<Mutex<u32>>,
    }

    impl MockEndpoint {
        fn new(id: u8) -> Self {
            Self {
                endpoint_id: [id; 32],
                calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl DeliveryEndpoint for MockEndpoint {
        fn endpoint_id(&self) -> [u8; 32] {
            self.endpoint_id
        }

        async fn attempt_store(
            &self,
            _mailbox: &DevMailboxId,
            _burst_cbor: &[u8],
        ) -> Result<(), DeliveryError> {
            *self.calls.lock().unwrap() += 1;
            Ok(())
        }

        async fn attempt_poll(
            &self,
            _mailbox: &DevMailboxId,
        ) -> Result<Vec<Vec<u8>>, DeliveryError> {
            *self.calls.lock().unwrap() += 1;
            Ok(Vec::new())
        }
    }

    // ── RelayEndpoint: endpoint_id is not derived from addr (design §3.2) ─────
    //
    // Flagged by security review: nothing in the type system stops a future
    // edit from deriving endpoint_id from addr (e.g. hash(addr)), which would
    // reintroduce the address-correlation-graph risk §3.2 exists to prevent.
    // Pin the required behavior explicitly: changing addr must never change
    // endpoint_id, and two endpoints at the same addr with different
    // operator-assigned tags must remain distinct pool keys.

    #[test]
    fn relay_endpoint_id_is_independent_of_address() {
        let tag = [42u8; 32];
        let a = RelayEndpoint::new(tag, "127.0.0.1:7700");
        let b = RelayEndpoint::new(tag, "127.0.0.1:9999");
        assert_eq!(
            a.endpoint_id(),
            b.endpoint_id(),
            "endpoint_id must be unaffected by a change in addr — it is an \
             independent operator-assigned tag, never derived from the address"
        );
        assert_ne!(a.addr(), b.addr());
    }

    #[test]
    fn relay_endpoint_at_same_address_can_have_distinct_tags() {
        let a = RelayEndpoint::new([1u8; 32], "127.0.0.1:7700");
        let b = RelayEndpoint::new([2u8; 32], "127.0.0.1:7700");
        assert_eq!(a.addr(), b.addr());
        assert_ne!(
            a.endpoint_id(),
            b.endpoint_id(),
            "distinct operator-assigned tags remain distinct pool keys even at \
             an identical address — the pool key is the tag, never the address"
        );
    }

    // ── io::Error -> DeliveryError mapping (pure, no network) ──────────────────

    #[test]
    fn io_error_kinds_map_to_expected_delivery_error_variants() {
        use std::io::{Error, ErrorKind};
        assert!(matches!(
            map_io_error(Error::from(ErrorKind::ConnectionRefused)),
            DeliveryError::ConnectionRefused
        ));
        assert!(matches!(
            map_io_error(Error::from(ErrorKind::TimedOut)),
            DeliveryError::Timeout
        ));
        assert!(matches!(
            map_io_error(Error::from(ErrorKind::UnexpectedEof)),
            DeliveryError::Protocol(_)
        ));
    }

    // ── Security fix: a hung relay must time out, not stall the caller ────────
    // Uses tokio's paused virtual time — advancing past RELAY_IO_TIMEOUT makes
    // the internal `tokio::time::timeout` fire without an actual multi-second
    // real-time wait.

    #[tokio::test(start_paused = true)]
    async fn with_io_timeout_returns_timeout_when_future_never_resolves() {
        let never = std::future::pending::<Result<(), DeliveryError>>();
        let task = tokio::spawn(with_io_timeout(never));
        tokio::time::advance(RELAY_IO_TIMEOUT + std::time::Duration::from_millis(100)).await;
        let result = task.await.unwrap();
        assert!(
            matches!(result, Err(DeliveryError::Timeout)),
            "a future that never resolves must be reported as a real timeout, \
             not left to hang the caller indefinitely"
        );
    }

    // ── Security fix: a hostile relay cannot force unbounded allocation ──────
    // A real TCP server plays the role of a malicious relay: accepts the poll
    // request, then replies with a crafted, wildly-oversized burst-length
    // header. attempt_poll must reject it before allocating that buffer.

    #[tokio::test]
    async fn attempt_poll_rejects_an_oversized_burst_length_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read and discard the poll request: [0x02][32 token].
            let mut req = [0u8; 33];
            let _ = stream.read_exact(&mut req).await;
            // Reply: count=1, then a single burst claiming u32::MAX bytes.
            stream.write_all(&1u32.to_le_bytes()).await.unwrap();
            stream.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        });

        let endpoint = RelayEndpoint::new([1u8; 32], addr.to_string());
        let mailbox = DevMailboxId::generate();
        let result = endpoint.attempt_poll(&mailbox).await;

        assert!(
            matches!(result, Err(DeliveryError::Protocol(_))),
            "an oversized burst-length header from an untrusted relay must be \
             rejected before allocating a buffer of that size, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn attempt_poll_rejects_an_oversized_burst_count_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 33];
            let _ = stream.read_exact(&mut req).await;
            // Claim an absurd number of bursts without ever sending any.
            stream.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        });

        let endpoint = RelayEndpoint::new([1u8; 32], addr.to_string());
        let mailbox = DevMailboxId::generate();
        let result = endpoint.attempt_poll(&mailbox).await;

        assert!(
            matches!(result, Err(DeliveryError::Protocol(_))),
            "an oversized burst-count header from an untrusted relay must be \
             rejected before allocating a Vec of that capacity, got: {result:?}"
        );
    }

    #[test]
    fn select_route_returns_receipt_bound_routes() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
        pool.add(MockEndpoint::new(1));
        pool.add(MockEndpoint::new(2));

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).expect("selection must succeed");
        assert_eq!(
            routes.len(),
            1,
            "RandomK(1) over 2 endpoints must select 1 route"
        );
    }

    #[test]
    fn record_delivery_success_via_receipt_updates_telemetry() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
        pool.add(MockEndpoint::new(1));

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        let route = routes.into_iter().next().unwrap();

        assert!(pool.record_delivery_success(&route.receipt).is_ok());
        let snap = pool.telemetry();
        assert_eq!(snap.admissible_response_total, 1);
    }

    #[test]
    fn record_delivery_failure_via_receipt_updates_telemetry() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
        pool.add(MockEndpoint::new(1));

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        let route = routes.into_iter().next().unwrap();

        assert!(pool.record_delivery_failure(&route.receipt).is_ok());
        let snap = pool.telemetry();
        assert_eq!(snap.admissible_failure_total, 1);
    }

    #[test]
    fn with_liveness_excludes_dead_endpoint_from_selection() {
        // RandomK(2) over exactly 2 endpoints selects both, every call —
        // deterministic, not a probabilistic RandomK(1) coin flip.
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(2), 16)
            .with_liveness(2, u64::MAX);
        let healthy = MockEndpoint::new(1);
        let dying = MockEndpoint::new(2);
        pool.add(healthy.clone());
        pool.add(dying.clone());

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        assert_eq!(
            routes.len(),
            2,
            "RandomK(2) over 2 endpoints must select both"
        );

        // Kill `dying` via two failed receipts (max_consecutive_failures = 2).
        for route in routes {
            if route.endpoint.endpoint_id() == dying.endpoint_id() {
                pool.record_delivery_failure(&route.receipt).unwrap();
            }
        }
        let routes2 = pool.select_route(&mut rng).unwrap();
        for route in &routes2 {
            if route.endpoint.endpoint_id() == dying.endpoint_id() {
                pool.record_delivery_failure(&route.receipt).unwrap();
            }
        }

        // After 2 consecutive failures, `dying` must no longer appear in selection.
        let routes3 = pool.select_route(&mut rng).unwrap();
        assert_eq!(
            routes3.len(),
            1,
            "dead endpoint must be filtered from selection"
        );
        assert_eq!(
            routes3[0].endpoint.endpoint_id(),
            healthy.endpoint_id(),
            "only the healthy endpoint may remain selectable"
        );
    }

    // ── Security invariant: at-most-once outcome per receipt (anti-steering) ──
    //
    // ADR stakes §2: routing must not be steerable by replaying/forging a
    // failure signal against a receipt that already resolved. A second
    // presentation of the same receipt must be rejected.

    #[test]
    fn recording_the_same_receipt_twice_is_rejected() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
        pool.add(MockEndpoint::new(1));

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        let route = routes.into_iter().next().unwrap();

        assert!(
            pool.record_delivery_failure(&route.receipt).is_ok(),
            "first presentation of a valid receipt must succeed"
        );
        assert_eq!(
            pool.record_delivery_failure(&route.receipt),
            Err(scp_provider_pool::AdmissibilityError::UnknownReceipt),
            "second presentation of an already-consumed receipt must be rejected — \
             this is what prevents an adversary from replaying a single real \
             failure into repeated routing-relevant liveness degradation"
        );
        let snap = pool.telemetry();
        assert_eq!(
            snap.admissible_failure_total, 1,
            "duplicate rejection must not double-count"
        );
    }

    // ── Security invariant: a tampered receipt is rejected (provider binding) ─

    #[test]
    fn a_receipt_tampered_to_a_different_provider_is_rejected() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
        pool.add(MockEndpoint::new(1));

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        let route = routes.into_iter().next().unwrap();
        let tampered = route.receipt.clone().with_provider_id([99u8; 32]);

        assert_eq!(
            pool.record_delivery_failure(&tampered),
            Err(scp_provider_pool::AdmissibilityError::ProviderMismatch),
            "a receipt claiming a different provider than the one it was issued for must be rejected"
        );
        // The original, untampered receipt must still be usable — proves rejection
        // did not corrupt or consume the legitimate outstanding entry.
        assert!(pool.record_delivery_failure(&route.receipt).is_ok());
    }

    // ── Security invariant: capacity refusal blocks selection AND accounting ──

    #[test]
    fn capacity_exhaustion_refuses_further_selection() {
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 1);
        pool.add(MockEndpoint::new(1));
        pool.add(MockEndpoint::new(2));

        let mut rng = seeded();
        let first = pool.select_route(&mut rng);
        assert!(
            first.is_ok(),
            "first selection within capacity must succeed"
        );

        let second = pool.select_route(&mut rng);
        assert!(
            matches!(
                second,
                Err(scp_provider_pool::AdmissibilityError::ReceiptCapacityExhausted)
            ),
            "second selection must be refused: capacity bound is 1 and one receipt is outstanding"
        );
    }

    // ── Security invariant: selection is not keyed to mailbox/recipient ───────
    //
    // §3.2 anti-correlation invariant: relay selection must be a function of
    // liveness + fresh per-attempt randomness only, never of the mailbox
    // token or recipient identity. `select_route(&mut self, rng)` takes no
    // mailbox/recipient parameter at all — there is no value in scope it
    // could key selection to (verify this by reading the call: the only
    // inputs are pool state and `rng`). This test pins the *behavioral*
    // consequence: two independently constructed pools with identical
    // endpoints and an identical RNG seed produce identical selection
    // sequences regardless of any "which conversation is this for" framing
    // a caller might have in mind — because no such framing can reach this
    // function's inputs.

    #[test]
    fn selection_is_a_pure_function_of_pool_state_and_rng_only() {
        fn build() -> DeliveryPool<MockEndpoint> {
            let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(1), 16);
            pool.add(MockEndpoint::new(1));
            pool.add(MockEndpoint::new(2));
            pool
        }

        // Two independent pools, identical setup, identical seed — standing
        // in for two different real send/receive contexts (different
        // mailboxes/recipients in the caller's world) that select_route()
        // has no way to distinguish, since it is never given either.
        let mut pool_context_a = build();
        let mut pool_context_b = build();
        let mut rng_a = seeded();
        let mut rng_b = seeded();

        let routes_a = pool_context_a.select_route(&mut rng_a).unwrap();
        let routes_b = pool_context_b.select_route(&mut rng_b).unwrap();

        assert_eq!(
            routes_a[0].endpoint.endpoint_id(),
            routes_b[0].endpoint.endpoint_id(),
            "identical (pool state, rng) must select the identical endpoint regardless of \
             which real conversation the caller has in mind — proving selection cannot be \
             keyed to a mailbox/recipient it is never given"
        );
    }

    // ── Endpoint identity: pool key is the random tag, not the address ────────

    #[test]
    fn pool_key_is_the_random_tag_not_derived_from_any_other_field() {
        // Two endpoints with different endpoint_id are distinct pool entries
        // even though nothing else distinguishes them structurally here —
        // proving the pool indexes purely on the operator-assigned tag.
        let mut pool = DeliveryPool::new(scp_provider_pool::SamplingStrategy::RandomK(2), 16);
        let a = MockEndpoint::new(1);
        let b = MockEndpoint::new(2);
        pool.add(a.clone());
        pool.add(b.clone());

        let mut rng = seeded();
        let routes = pool.select_route(&mut rng).unwrap();
        let mut ids: Vec<[u8; 32]> = routes.iter().map(|r| r.endpoint.endpoint_id()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![a.endpoint_id(), b.endpoint_id()],
            "both distinct tags must be present as distinct pool entries"
        );
    }
}
