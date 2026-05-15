# SCP Threat Model

## Priority Threats

| Threat | Priority |
|--------|----------|
| Commercial surveillance | High |
| Platform capture | High |
| Hostile intermediaries | High |
| Spam / coercive contact | High |
| State surveillance | Moderate / High |
| Nation-state compromise | Limited defense |

## Protocol Boundaries

SCP does NOT promise:
- perfect anonymity,
- invisible existence,
- endpoint compromise immunity.

## Defense Strategy per Phase

| Phase | Threat Focus |
|-------|-------------|
| 0 | Key material compromise (hardware enclave, zeroize) |
| 1 | Replay attacks, stale consent state |
| 2 | Relay compromise, route inference |
| 3 | Device theft, cold-boot attacks |
| 4 | Recovery impersonation, guardian coercion |
| 5 | Traffic correlation, graph reconstruction |
| 7 | Formal verification of all state transitions |
