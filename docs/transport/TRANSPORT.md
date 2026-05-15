# SCP Flash Tunnel Transport Model

## Doctrine

SCP does not maintain persistent transport tunnels.
- Trust persists.
- Transport dissolves.

## Flash Session Lifecycle

### Step 1 — State Retrieval
Sender retrieves: recipient operational identity, vitality state, routing hints.

### Step 2 — Ephemeral Session Generation
Generate: ephemeral session key, route identifier, relay path, freshness nonce.

### Step 3 — Transmission Burst
Payload: encrypted, signed, replay-protected.

### Step 4 — Warm Memory Cache
Session state retained temporarily (5–15 minutes recommended).  
Purpose: reduce handshake overhead, reduce latency, preserve calm UX.

### Step 5 — Session Dissolution
Transport state destroyed: relay memory purged, route invalidated, session keys expired.

## Vitality States

| State | Meaning |
|-------|---------|
| Active | High vitality |
| Warm | Stable low-frequency trust |
| Dormant | Cooling relationship |
| Suspended | Reduced visibility |
| Severed | Explicit revocation |
| Burned | Security distrust state |

## Vitality Function

`V(t, i, r, p)` — probabilistic, non-binary, entropy-sensitive.

| Variable | Meaning |
|----------|---------|
| t | Time since reaffirmation |
| i | Interaction entropy |
| r | Reciprocal participation quality |
| p | Protocol perturbation factor |
