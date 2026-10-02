# MacNexa Network Protocol Specification

MacNexa utilizes a binary-framed, encrypted TCP protocol over the local network combined with Bonjour (mDNS) service discovery.

---

## 1. Transport & Framing

- **Transport**: Standard TCP stream on port `57842` (with fallback).
- **Service Discovery**: Advertised via Bonjour as `_macnexa._tcp.`.
- **Binary Frame Layout**:
  Every frame begins with a fixed 4-byte big-endian unsigned integer indicating the length of the JSON payload, followed by the UTF-8 encoded JSON body:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length (N Bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    JSON Payload (N Bytes)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Bounds Enforcement**:
  - Maximum Frame Length (`kMNMaxFrameSize`): **65,536 bytes (64 KB)**.
  - Sockets enforce a **5-second timeout** (`SO_RCVTIMEO`, `SO_SNDTIMEO`) for automated machine requests, and an extended **60-second timeout** during human-in-the-loop SAS pairing code verification.

---

## 2. Pairing Sequence & Message Formats

MacNexa enforces a strict **Exchange First, Verify Concurrently, Confirm Authenticated** pairing handshake:

```
 Initiator (Mac A)                                              Receiver (Mac B)
         |                                                              |
         | ---- 1. pairKeyExchange (A's PubKey, peerId, peerName) ----> |
         | <--- 2. pairKeyExchangeResponse (B's PubKey, accepted:true) - |
         |                                                              |
         | [Both derive shared secret & compute identical 6-digit SAS]  |
         | [Both display 6-digit code on screen for user comparison]    |
         |                                                              |
         | ---- 3. pairConfirm (A accepted, HMAC-SHA256 AuthTag) -----> |
         |                                         [B verifies A's tag] |
         |                                       [B waits for user OK]  |
         |                                          [B persists trust]  |
         | <--- 4. pairConfirmResponse (B accepted, AuthTag) ---------- |
         |                                                              |
[A verifies B's tag]                                                    |
[A persists trust]                                                      |
```

### 2.1. Pairing Key Exchange (`pairKeyExchange`)
Initiated by Mac A to exchange ephemeral ECDH (P-256) public keys.
```json
{
  "action": "pairKeyExchange",
  "peerId": "D7DE7B59-3B2B-439A-A42B-6338A6D2313C",
  "peerName": "MacBook Pro",
  "pubKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
}
```

### 2.2. Pairing Key Exchange Response (`pairKeyExchangeResponse`)
Returned immediately by Mac B with its own ephemeral ECDH public key, allowing both sides to derive the shared secret and display the 6-digit SAS code concurrently.
```json
{
  "action": "pairKeyExchangeResponse",
  "accepted": true,
  "peerId": "8F91B012-4C1A-48B8-9366-21D6385419AA",
  "peerName": "Mac Studio",
  "pubKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
}
```

### 2.3. Initiator Authenticated Confirmation (`pairConfirm`)
Sent by Mac A after its user verifies the 6-digit SAS code and clicks "Confirm & Trust". Authenticated using `HMAC-SHA256(sharedSecret, "MacNexa-Pair-Confirm-v1:initiator:peerA:peerB")`:
```json
{
  "action": "pairConfirm",
  "accepted": true,
  "authTag": "f9e2b1...=="
}
```

### 2.4. Receiver Authenticated Confirmation Response (`pairConfirmResponse`)
Returned by Mac B after verifying Mac A's confirmation tag and obtaining local user confirmation. Mac B persists trust before replying; Mac A persists trust upon verifying Mac B's tag:
```json
{
  "action": "pairConfirmResponse",
  "accepted": true,
  "authTag": "a8c3d4...=="
}
```

### 2.3. Authenticated Encrypted Envelope (`encryptedEnvelope`)
Used for all operational commands once mutual trust is established. The inner payload is encrypted with AES-256 and authenticated with HMAC-SHA256:
```json
{
  "action": "encryptedEnvelope",
  "senderId": "D7DE7B59-3B2B-439A-A42B-6338A6D2313C",
  "nonce": 1727649821001,
  "timestamp": 1727649821.45,
  "iv": "dGVzdF9pdl8xNmJ5dGVzISE=",
  "ciphertext": "k3f8d...==",
  "tag": "a8f3b9c...=="
}
```

### 2.4. Decrypted Switch Request Payload (Inner JSON)
The plaintext decrypted from `ciphertext`:
```json
{
  "action": "requestSwitch",
  "devices": [
    {
      "address": "68-fe-f7-77-fe-fa",
      "name": "Suraj’s Magic Keyboard",
      "type": "keyboard",
      "battery": 88
    },
    {
      "address": "18-7e-b9-69-fc-37",
      "name": "Suraj Khadka’s Trackpad",
      "type": "trackpad",
      "battery": 94
    }
  ]
}
```

### 2.5. Authenticated Switch Acknowledgment (`switchAck`)
Returned by the target Mac confirming peripheral acquisition status. The response is transmitted as an authenticated `encryptedEnvelope` (AES-256 + HMAC-SHA256 Encrypt-then-MAC) and cryptographically bound to the peer, session, and exact request nonce & HMAC tag:
```json
{
  "action": "switchAck",
  "requestNonce": 1727649821001,
  "requestTag": "a8f3b9c...==",
  "success": true,
  "error": null
}
```
The initiating Mac decrypts the envelope, verifies constant-time HMAC-SHA256 authenticity and monotonic replay freshness, and validates that `requestNonce` and `requestTag` match the request sent in that session. Unauthenticated responses, plaintext responses, or binding mismatches trigger an immediate local rollback to recover accessories.

---

## 3. Protocol Security & Validation Pipeline

1. **Replay Validation**:
   - Packets must have $\text{timestamp}$ within 30 seconds of local time.
   - Nonce must be strictly greater than $\text{lastSeenNonce}$ for that peer ID.
2. **Cryptographic Tag Verification**:
   - Subkey derivation: $K_{\text{mac}} = \text{HMAC-SHA256}(K, \text{"macnexa-mac"})$.
   - Tag computed over: $\text{IV} \parallel \text{Ciphertext} \parallel \text{Nonce} \parallel \text{Timestamp} \parallel \text{SenderID}$.
   - Verified via constant-time comparison (`timingsafe_bcmp`).
3. **Decryption**:
   - Subkey derivation: $K_{\text{enc}} = \text{HMAC-SHA256}(K, \text{"macnexa-enc"})$.
   - Decrypted via AES-256-PKCS7 with verified IV.
