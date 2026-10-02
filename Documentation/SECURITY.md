# MacNexa Security Architecture & Threat Model

MacNexa can release and connect input devices (keyboard and mouse/trackpad) remotely over the local network. Input devices have direct access to system control, keystrokes, and authentication prompts; therefore, **mutual trust, message confidentiality, payload integrity, and abuse resistance are safety-critical**.

This document outlines the security architecture, threat model, cryptographic primitives, and implementation controls protecting MacNexa against local and network adversaries.

---

## 1. Threat Model & Adversary Capabilities

We assume an adversary with the following capabilities:

1. **Local Network Sniffer (Passive Eavesdropper)**: An attacker on the same local network (Wi-Fi or Ethernet) capable of monitoring all unencrypted packets using packet capture tools (e.g. Wireshark, `tcpdump`).
2. **Active Man-in-the-Middle (MitM)**: An attacker capable of ARP spoofing, DNS poisoning, or proxying TCP traffic between two Macs on the local network.
3. **Replay & Injection Attacker**: An adversary who captures previously transmitted authenticated frames and replays them at a later time to forcibly disconnect devices or cause denial of service.
4. **Local Host Malware / Rogue Software**: An untrusted process or malicious script running on the same Mac attempting to read credentials, stolen keys, or private profiles from disk.
5. **Denial-of-Service (DoS) Flooder**: An attacker attempting to crash the service, exhaust memory buffers, or lock the user interface with modal prompt spam.

---

## 2. Threat-to-Control Matrix

| Threat | Adversary Objective | Defense Mechanism | Cryptographic Implementation |
| :--- | :--- | :--- | :--- |
| **Cleartext Sniffing** | Capture shared secrets or monitor device MAC addresses. | **Zero Key Transmission + Full AES-256 Payload Encryption** | Diffie-Hellman Key Exchange (ECDH P-256) + AES-256-PKCS7. |
| **Man-in-the-Middle (MitM)** | Intercept pairing handshake and inject rogue keys. | **Short Authentication String (SAS)** | 6-digit numeric SAS code visually confirmed by user on both screens. |
| **Replay Attacks** | Replay valid switch packets hours later to hijack peripherals. | **Monotonic Sequence Nonces + Timestamp Skew Windows** | Strict nonces ($\text{nonce} > \text{lastSeen}$) + 30-second timestamp drift limit. |
| **Nonce Poisoning / Replay DoS** | Send unauthenticated envelopes with huge nonces to block legitimate traffic. | **Post-Authentication Nonce Commit** | Nonce state mutated strictly after constant-time HMAC-SHA256 verification passes. |
| **Payload Tampering** | Modify destination device list or inject arbitrary actions. | **Encrypt-then-MAC (EtM)** | HMAC-SHA256 signature calculated over (IV $\parallel$ Ciphertext $\parallel$ Nonce $\parallel$ Timestamp $\parallel$ SenderID). |
| **Timing Side-Channels** | Infer keys via byte-by-byte comparison timing differences. | **Constant-Time Memory Comparison** | Darwin kernel-grade `timingsafe_bcmp`. |
| **Local Key Extraction** | Read stored pairing credentials from plaintext plists. | **Injected FileSecretStore (AES-256 + HMAC)** | Atomic writes, 0600 file permissions, 0700 directory permissions, per-install seed. |
| **Network Denial of Service** | Freeze socket threads or spam alert modals. | **Strict Frame Caps, Timeouts & Rate Limiters** | Max 64 KB frames, 3-second `SO_RCVTIMEO`/`SO_SNDTIMEO`, 10s pairing cooldown. |

---

## 3. Cryptographic Primitives & Key Lifecycles

### 3.1. Pairing Handshake (Ephemeral ECDH P-256)
Master shared secrets are **never transmitted over the network**. When two Macs pair:

1. **Mac A** generates an ephemeral keypair $(sk_A, pk_A)$ using NIST P-256 (`kSecAttrKeyTypeECSECPrimeRandom`).
2. **Mac A** sends only its public key $pk_A$ to **Mac B**.
3. **Mac B** generates its own ephemeral keypair $(sk_B, pk_B)$ and computes the shared secret:
   $$K = \text{ECDH}(sk_B, pk_A)$$
4. **Mac B** returns its public key $pk_B$ to **Mac A**.
5. **Mac A** computes the exact same shared secret:
   $$K = \text{ECDH}(sk_A, pk_B)$$
6. Both Macs derive the 6-digit Short Authentication String (SAS):
   $$\text{Context} = \text{"MacNexa-SAS-v1:"} \parallel \min(\text{ID}_A, \text{ID}_B) \parallel \max(\text{ID}_A, \text{ID}_B)$$
   $$\text{Digest} = \text{HMAC-SHA256}(K, \text{Context})$$
   $$\text{Code} = (\text{BigEndianUInt32}(\text{Digest}[0..3]) \pmod{900000}) + 100000$$
7. Both users visually verify the 6-digit code on their respective screens. If a MitM attacker intervened, the derived keys diverge and the codes will not match.
8. Upon user confirmation, $K$ is saved into the injected **File Secret Store** (`MNFileSecretStore`).

### 3.2. Authenticated Encryption & Inbound Verification Sequence (EtM)
All operational commands (e.g. `requestSwitch`, device handoff payloads) follow a strict, fail-closed verification sequence to prevent both payload tampering and state-poisoning DoS attacks:

1. **Subkey Derivation**:
   - $K_{\text{enc}} = \text{HMAC-SHA256}(K, \text{"macnexa-enc"})$
   - $K_{\text{mac}} = \text{HMAC-SHA256}(K, \text{"macnexa-mac"})$
2. **IV Generation**: A 16-byte cryptographically secure pseudorandom IV is generated via `arc4random_buf`.
3. **Outbound Encryption**: Plaintext JSON is encrypted with AES-256:
   $$C = \text{AES-256-PKCS7}(K_{\text{enc}}, \text{IV}, \text{Plaintext})$$
   $$\text{Tag} = \text{HMAC-SHA256}(K_{\text{mac}}, \text{IV} \parallel C \parallel \text{Nonce} \parallel \text{Timestamp} \parallel \text{SenderID})$$
4. **Inbound Replay Pre-Check (Read-Only)**: The receiving Mac verifies timestamp freshness ($|\text{now} - \text{timestamp}| \le 30\text{s}$) and monotonic nonce freshness ($\text{nonce} > \text{lastSeen}$). **Crucially, the nonce state is NOT mutated yet.**
5. **Constant-Time Verification**: The receiving Mac calculates expected $\text{Tag}$ and verifies it via `timingsafe_bcmp`. Any tampering or forgery causes immediate rejection before state update or decryption.
6. **Post-Authentication Nonce Commit**: Only after HMAC verification succeeds is the new nonce recorded in `lastSeenNonces[peerID] = nonce`. Unauthenticated network attackers sending envelopes with huge nonces cannot poison peer state or cause DoS.
7. **Inbound Decryption**: Once authenticated, the plaintext payload is decrypted via AES-256-CBC.

---

## 4. Storage & Persistence Security

- **Injected Secret Store Interface (`MNSecretStoring`)**:
  - `MNSecurity` delegates secret persistence to an injected `id<MNSecretStoring>` store (defaults to `MNFileSecretStore`), eliminating hard-coded Keychain dependencies and enabling testing/mock injection.
- **Enforced POSIX Permissions**:
  - Storage directory (`~/Library/Application Support/MacNexa`): Strictly locked to `0700` (`rwx------`).
  - Seed file (`secrets.seed`): Cryptographically secure 256-bit random entropy, locked to `0600` (`rw-------`).
  - Encrypted file (`secrets.enc`): Authenticated container (AES-256-CBC + HMAC-SHA256 Encrypt-then-MAC), written with `NSDataWritingAtomic` and locked to `0600` (`rw-------`).
- **Safe Corruption Handling & Automatic Quarantine**:
  - Truncated files, invalid headers, or failed HMAC checks are **never unhandled** and will never crash the daemon.
  - Corrupted files are safely quarantined to `secrets.enc.corrupt.<timestamp>` to preserve forensics and clear blocked state for future pairing.
- **Error Propagation to UI**:
  - All storage failures (permission denials, disk write errors, corruption) return rich `NSError` instances.
  - Errors reach the user via native `NSAlert` dialogs during pairing/unpairing and a menu bar warning banner with one-click recovery.
- **Application Preferences**: `NSUserDefaults` (`com.macnexa.app`) stores only non-sensitive display metadata (e.g. peer machine names, pairing timestamps). No private keys or authentication tokens are ever stored in plaintext plists.

---

## 5. Denial-of-Service & Abuse Defenses

1. **Socket Timeouts**:
   - Sockets enforce strict 3-second read/write timeouts (`SO_RCVTIMEO`, `SO_SNDTIMEO`).
   - Prevents slowloris attacks and hangs from incomplete network frames.
2. **Frame Size Bounds**:
   - Packets are bounded by a strict maximum limit of **64 KB** (`kMNMaxFrameSize`).
   - Any frame specifying a length $> 64\text{ KB}$ is rejected immediately, preventing memory exhaustion attacks.
3. **Pairing Request Rate Limiting**:
   - Inbound pairing prompts are throttled to a minimum interval of 10 seconds per prompt.
   - Prevents rogue clients from spamming pairing dialogs to lock the user's interface.

---

## 6. Privacy & Data Minimization

- **Zero Cloud Dependence**: MacNexa communicates strictly peer-to-peer over the local subnet. No telemetry, crash reports, or analytics are sent to any remote server.
- **No Keystroke Logging**: MacNexa operates exclusively at the Bluetooth connection management layer (`IOBluetooth` / `IOKit`). It never inspects, captures, or logs keyboard or mouse input events.
