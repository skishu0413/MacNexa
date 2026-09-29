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
  - Sockets enforce a **3-second timeout** (`SO_RCVTIMEO`, `SO_SNDTIMEO`) to prevent connection starvation.

---

## 2. Message Formats

### 2.1. Pairing Request (`pairRequest`)
Initiated by Mac A to request mutual authentication with Mac B.
```json
{
  "action": "pairRequest",
  "peerId": "D7DE7B59-3B2B-439A-A42B-6338A6D2313C",
  "peerName": "MacBook Pro",
  "pubKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
}
```

### 2.2. Pairing Response (`pairResponse`)
Returned by Mac B upon verifying and accepting the pairing request.
```json
{
  "action": "pairResponse",
  "accepted": true,
  "pubKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."
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

### 2.5. Switch Acknowledgment (`switchAck`)
Returned by the target Mac confirming whether peripheral acquisition succeeded:
```json
{
  "action": "switchAck",
  "success": true,
  "error": null
}
```

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
