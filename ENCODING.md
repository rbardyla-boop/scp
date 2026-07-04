# SCP Canonical Encoding Specification (v0)

This document defines the wire byte layout for all SCP protocol messages.
It is implementation-independent: any SCP implementation in any language must produce
byte-identical outputs for identical inputs. The Rust codebase is the reference
implementation; this document is the authoritative encoding contract.

## 1. Endian Conventions

- **All multi-byte integers: little-endian** (u64 nonces, u64 expires_at, u64 rotation
  nonce, u32 TCP frame length)
- **Exception:** Noise Protocol frame length prefix uses **big-endian u16** (inherited
  from the Noise Protocol Framework specification; preserved for wire compatibility)

## 2. Transcript Layout

Transcripts are the cryptographic binding between session identity and transport
material. Two versions are defined; v2 is a strict semantic extension of v1.

### V1 (63 bytes)

| Offset | Length | Field              | Encoding           |
|--------|--------|--------------------|--------------------|
| 0      | 4      | magic              | `"SCPt"` (ASCII)   |
| 4      | 1      | format             | `0x01`             |
| 5      | 16     | route_id           | raw bytes          |
| 21     | 8      | nonce              | u64 little-endian  |
| 29     | 32     | recipient_ops_pub  | raw bytes          |
| 61     | 1      | vitality_byte      | see §6             |
| 62     | 1      | protocol_version   | raw u8             |

### V2 (95 bytes)

V2 extends V1: bytes `[0..63]` are identical in layout, with format byte `0x02`.

| Offset | Length | Field                | Encoding           |
|--------|--------|----------------------|--------------------|
| 0–62   | 63     | (same as V1)         | format byte = 0x02 |
| 63     | 32     | sender_ephemeral_pub | raw bytes          |

**Invariant:** `v1[5..63] == v2[5..63]` for all identical base inputs. V2 is a strict
semantic extension — no shared field offsets change between versions. Property test:
`transcript_v1_is_prefix_of_v2_except_format_byte` in `test/tests/property.rs`.

## 3. Signing Message Layouts

Signing messages are the pre-image inputs to Ed25519 signatures. All lengths are fixed.

### handshake_sig_message (67 bytes)

| Offset | Length | Field      | Encoding                            |
|--------|--------|------------|-------------------------------------|
| 0      | 27     | prefix     | `"scp:handshake-ephemeral:v1:"` ASCII |
| 27     | 32     | pub_key    | X25519 public key, raw bytes        |
| 59     | 8      | expires_at | u64 little-endian                   |

### registration_message (96 bytes)

| Offset | Length | Field                | Encoding  |
|--------|--------|----------------------|-----------|
| 0      | 32     | k_root_pub           | raw bytes |
| 32     | 32     | k_ops_pub            | raw bytes |
| 64     | 32     | recovery_policy_hash | raw bytes |

### rotation_message (72 bytes)

| Offset | Length | Field       | Encoding          |
|--------|--------|-------------|-------------------|
| 0      | 32     | old_ops_pub | raw bytes         |
| 32     | 32     | new_ops_pub | raw bytes         |
| 64     | 8      | nonce       | u64 little-endian |

## 4. Relay Framing

Two framing schemes exist — one per relay transport. They intentionally differ in
endian and header width.

### TCP Relay Frame

| Offset | Length | Field          | Encoding           |
|--------|--------|----------------|--------------------|
| 0      | 4      | payload_length | u32 little-endian  |
| 4      | N      | payload        | raw bytes          |

### Noise Protocol Frame

| Offset | Length | Field          | Encoding          |
|--------|--------|----------------|-------------------|
| 0      | 2      | message_length | u16 big-endian    |
| 2      | N      | message        | raw bytes         |

> **Note:** TCP uses LE u32; Noise uses BE u16. This inconsistency is preserved to
> avoid a breaking wire protocol change. Unification is planned. The inconsistency is
> documented in `scp-wire-format/src/constants.rs` and tested in `wire_vectors.rs`.

## 5. State Commitment Encoding (v0)

`RecipientState::commitment()` returns a 32-byte BLAKE3 hash that binds all canonical
state fields. The encoding is consensus-relevant: future federation, audit proofs, and
zk attestations depend on this being stable.

**Hash input (concatenated in order):**

| Field            | Length | Encoding                         |
|------------------|--------|----------------------------------|
| ops_pub          | 32     | raw bytes                        |
| vitality_byte    | 1      | canonical wire byte (see §6)     |
| ephemeral_present| 1      | `0x01` if Some, `0x00` if None   |
| ephemeral.pub_key| 32     | raw bytes (only if present)      |
| ephemeral.expires_at | 8  | u64 little-endian (only if present) |

> **Future note:** `ephemeral_present` is a binary flag. If future versions add
> algorithm negotiation, PQ ephemerals, or multi-ephemeral bundles, replace this byte
> with an `ephemeral_mode_byte` encoding capability sets. Any such change is a
> versioned breaking change.

## 6. Vitality Wire Byte Assignments

| State     | Wire Byte |
|-----------|-----------|
| Active    | `0x00`    |
| Warm      | `0x01`    |
| Dormant   | `0x02`    |
| Suspended | `0x03`    |
| Severed   | `0x04`    |
| Burned    | `0x05`    |

## 7. Canonical Test Vectors

All canonical vectors are anchored in `test/tests/wire_vectors.rs`. Standard inputs:

```
route_id              = [0x01; 16]
nonce                 = 0x0102030405060708u64
recipient_ops_pub     = [0x02; 32]
sender_ephemeral_pub  = [0x03; 32]
k_root_pub            = [0x01; 32]
k_ops_pub             = [0x02; 32]
recovery_policy_hash  = [0x03; 32]
old_ops_pub           = [0x01; 32]
new_ops_pub           = [0x02; 32]
pub_key (handshake)   = [0x01; 32]
expires_at            = 2000u64
vitality_byte         = 0x00 (Active)
protocol_version      = 0x01
```

### Transcript V1 (63 bytes)

```
53 43 50 74 01                   — "SCPt" + format 0x01
01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01          — route_id [0x01; 16]
08 07 06 05 04 03 02 01          — nonce 0x0102030405060708 LE
02 02 02 02 02 02 02 02
02 02 02 02 02 02 02 02
02 02 02 02 02 02 02 02
02 02 02 02 02 02 02 02          — recipient_ops_pub [0x02; 32]
00 01                            — vitality 0x00, version 0x01
```

### Transcript V2 (95 bytes)

Same as V1 with `format = 0x02` at offset 4, followed by:
```
03 03 03 03 03 03 03 03
03 03 03 03 03 03 03 03
03 03 03 03 03 03 03 03
03 03 03 03 03 03 03 03          — sender_ephemeral_pub [0x03; 32]
```

### handshake_sig_message (67 bytes)

```
73 63 70 3a 68 61 6e 64
73 68 61 6b 65 2d 65 70
68 65 6d 65 72 61 6c 3a
76 31 3a                         — "scp:handshake-ephemeral:v1:"
01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01
01 01 01 01 01 01 01 01          — pub_key [0x01; 32]
d0 07 00 00 00 00 00 00          — expires_at 2000 LE
```

### registration_message (96 bytes)

`[0x01; 32] || [0x02; 32] || [0x03; 32]`

### rotation_message (72 bytes)

`[0x01; 32] || [0x02; 32] || 08 07 06 05 04 03 02 01`

### TCP frame — `encode_tcp_frame(b"scp:v1")`

```
06 00 00 00              — length 6, u32 LE
73 63 70 3a 76 31        — "scp:v1"
```

### Noise frame — `encode_noise_frame(b"scp:v1")`

```
00 06                    — length 6, u16 BE
73 63 70 3a 76 31        — "scp:v1"
```

### State commitment golden vector

See `test/tests/state.rs :: state_commitment_matches_known_vector`.

```
ops_pub    = [0x55; 32]
vitality   = Active (0x00)
ephemeral  = Some(pub_key=[0xaa; 32], expires_at=9_999_999)

BLAKE3 → e1 1f ff 74 97 9a 05 45
          48 67 aa 30 63 cb 56 45
          5a c0 74 c8 fb b4 12 e2
          a1 23 89 9d e8 f2 d2 1e
```

## 8. Version Negotiation

`WireVersion::negotiate(local, remote)` returns `min(local, remote)`.

Currently only `WireVersion::V1` is defined. The v2 bilateral DH path is a
transport-layer feature, not a wire-version gate — it uses the same framing.

## 9. Compatibility Guarantee

Any encoding change — field reordering, endian flip, length change, new field
insertion — **must**:

1. Increment the relevant format/version byte
2. Add a new canonical test vector in `test/tests/wire_vectors.rs`
3. Update this document with the new layout table and vector
4. Record the migration rule (what old bytes mean, what new bytes mean)

The property test `transcript_v1_is_prefix_of_v2_except_format_byte` in
`test/tests/property.rs` mechanically enforces the extension invariant for transcripts.
The golden vectors in `wire_vectors.rs` and `state.rs` are the compatibility contracts
for all other message types.
