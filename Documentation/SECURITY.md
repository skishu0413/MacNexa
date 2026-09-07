# Security

MacNexa can release input devices remotely over the local network, so trust,
message integrity, and abuse resistance are safety-critical. This document
describes the implemented controls and how they map to the threat model (spec §13).

See `.skills/security-review.md` for the checklist applied to every change.

## Trust model

- A peer can issue commands ONLY after explicit, user-authorized pairing
  (spec §14). Pairing binds a stable `peerId` to that peer's Curve25519 public
  key and stores it in the `TrustStore`.
- The system fails closed: any sender not present in the `TrustStore` is
  rejected (`ProtocolError.untrustedSender`). There is no default-allow path.
- Trust can be revoked; a revoked peer immediately loses command authority.
- Pairing is MITM-resistant: the 6-digit verification code is a short
  authentication string derived from a hash binding BOTH Macs' public keys and
  nonces. If an attacker substitutes a key while relaying, the codes shown on
  each Mac differ and the user declines.

## Command validation pipeline (fail-closed)

Every inbound message passes through `CommandValidator.validate` before any
action is taken. It enforces the spec §16 order and rejects at the first failure:

1. **Structure** — supported protocol version, minimum nonce entropy, size bounds.
2. **Trusted sender** — `senderId` must resolve to a `TrustedPeer`.
3. **Authentication** — HMAC-SHA256 over the canonical `signedData()`, verified
   with the key derived from *that trusted peer's* public key. This binds the
   claimed `senderId` to real key material, so a valid tag from any other key is
   rejected (defeats sender spoofing).
4. **Freshness + replay** — timestamp must be within the skew window and the
   `messageId` must not have been seen before.
5. **Rate limit** — control commands (RELEASE/CONNECT/SWITCH) are throttled per
   sender to blunt denial-of-service floods.

A command is executed only if all five checks pass.

## Threat → control mapping (spec §13)

| Threat | Control |
|--------|---------|
| Unauthorized local peer | TrustStore membership required; fail closed |
| Message spoofing | senderId bound to trusted key via HMAC verification |
| Replay attack | messageId dedup + timestamp window (ReplayProtection) |
| Tampering | HMAC-SHA256 over canonical signed representation |
| Secret extraction | Keys/secrets in Keychain only; never UserDefaults/logs/Bonjour |
| Denial of service | Frame size cap on decode + per-sender rate limiting |

## Cryptography

- Curve25519 key agreement + HKDF-SHA256 derives a per-peer authentication key.
- HMAC-SHA256 authenticates messages; verification is constant-time and the tag
  length is validated before comparison.
- Nonces are generated from a secure RNG with enforced minimum entropy.
- Public keys are length-validated before use.

## Storage

- By default, long-term private keys and shared secrets live only in the
  Keychain (OS-managed, hardware-backed encryption at rest).
- No secrets are logged (OSLog uses privacy redaction) or advertised via Bonjour.

### Keychain-free fallback (MDM / locked-down Macs)

On managed Macs the Keychain is often blocked by policy, which would otherwise
prevent the app from persisting its identity or trusted peers at all. For those
environments there is an encrypted file store (`FileSecretStore`):

- Enable explicitly with `MACNEXA_NO_KEYCHAIN=1`, or the app falls back to it
  automatically when a Keychain read/write probe fails at launch.
- Secrets are stored in `~/Library/Application Support/MacNexa/secrets.enc`,
  encrypted with AES-GCM using a per-install random key in `secrets.seed`. Both
  files are written atomically with `0600` permissions and file protection.
- Tradeoff: unlike the Keychain, the encryption key material lives on disk next
  to the ciphertext, so this is weaker than Keychain storage. It protects
  against casual disk inspection and accidental exposure, not against an
  attacker with full read access to the user's home directory. It is used only
  when the Keychain is unavailable or explicitly opted out.

## Hardening / platform

- App Sandbox enabled with least-privilege entitlements (network client/server,
  bluetooth) and Hardened Runtime.
- Distribution builds are signed and notarized (spec §44).

## Known limitations / next steps

- Replay state is currently in-memory; it should be persisted (or bound to a
  transaction epoch) so it survives reconnects and app restarts.
- The pairing handshake UI (code verification, public-key exchange) and the
  Keychain-backed store are the next security tasks per the spec phases.
- Hardware-level Bluetooth HID handoff behavior must be validated on real
  devices (spec §49) — a stranded-peripheral state is a safety concern handled
  by rollback in the switching layer.

MacNexa collects no telemetry and no user input content (spec §48).
