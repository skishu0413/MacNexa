# MacNexa Architecture & Subsystem Specification

MacNexa is architected as a lightweight, native macOS menu-bar utility designed for zero-overhead peripheral handoff, resilience, and cryptographic security across all modern macOS versions.

---

## 1. System Overview

MacNexa is comprised of two core components:

1. **Universal Native Engine (`MacNexa/Native/`)**:
   - Zero-dependency Objective-C engine utilizing Apple system frameworks (`Cocoa`, `IOBluetooth`, `IOKit`, `Security`).
   - Self-contained compilation with `clang` in under 3 seconds.
   - Operates as a native background daemon (`LSUIElement = true`) with a responsive menu-bar UI.
2. **Core Verification Engine (`MacNexaCore/`)**:
   - Swift Package containing hardware-independent business logic, data models, state machines, and unit tests.

---

## 2. Core Subsystems

```
┌────────────────────────────────────────────────────────────────────────┐
│                          MacNexa Application                           │
├────────────────────┬────────────────────┬──────────────────────────────┤
│  User Interface    │  Bluetooth Engine  │     Networking & Security    │
│  (MNMenuController)│(MNBluetoothManager)│     (MNNetwork & MNSecurity) │
├────────────────────┼────────────────────┼──────────────────────────────┤
│ • NSStatusItem     │ • IOBluetoothDevice│ • Bonjour Discovery          │
│ • Accessory list   │ • Silent Pairing   │ • Hardened BSD Sockets       │
│ • Battery display  │ • Device Unpairing │ • Ephemeral ECDH (P-256)     │
│ • SAS verification │ • IOKit Battery    │ • AES-256 + HMAC-SHA256 EtM  │
│   modals (NSAlert) │ • Device Profiles  │ • Injected File Secret Store │
└────────────────────┴────────────────────┴──────────────────────────────┘
```

### 2.1. User Interface (`MNMenuController`)
- **Status Item**: Native macOS menu-bar status item displaying a clean, unobtrusive keyboard icon.
- **Dynamic Menu**:
  - Live accessory list showing connected keyboards, trackpads, and mice with exact battery percentages (`🔋 88%`, `🪫 18% Low`).
  - Auto-discovered and trusted peer list showing connectivity status (`Online` / `Offline`) with direct unpair/forget options.
  - Active storage issue warning banner if directory permissions, corruption, or write failures occur.
  - One-click peripheral reconnection button (`⚡ Connect / Reconnect Accessories`).
- **Modal Presenter**: Displays high-priority verification dialogs (`NSAlert`) during mutual pairing to visually confirm the 6-digit Short Authentication String (SAS).

### 2.2. Bluetooth Engine (`MNBluetoothManager`)
- **Device Discovery**: Scans `[IOBluetoothDevice pairedDevices]` and `[IOBluetoothDevice recentDevices:0]` to detect Apple Magic accessories.
- **Silent Pairing**: Conforms to `IOBluetoothDevicePairDelegate` and automatically confirms Secure Simple Pairing (SSP) by invoking `replyUserConfirmation:YES` on system callbacks, preventing user confirmation dialogs.
- **Accessory Release & Unpairing**:
  - Drops connection via `[device closeConnection]`.
  - Removes pairing bond via private SPI `[device performSelector:NSSelectorFromString(@"remove")]`.
  - Persists device MAC addresses and profiles in `NSUserDefaults` (`com.macnexa.remembered_accessories`) so unbonded devices remain recognizable and re-connectable.
- **Battery Extraction**:
  - Queries `batteryPercentSingle` and `batteryPercentCombined` on `IOBluetoothDevice`.
  - Inspects `AppleDeviceManagementHIDEventService` via IOKit to read `BatteryPercent`.
  - Automatically caches the last known percentage in `NSUserDefaults` (`com.macnexa.last_battery.<addr>`).

### 2.3. Security & Trust Engine (`MNSecurity`)
- **Node Identity**: Each Mac maintains a stable UUID identifier (`localPeerId`) and localized host name.
- **Ephemeral Key Exchange**: Generates NIST P-256 keypairs on demand via `SecKeyCreateRandomKey` and performs Diffie-Hellman via `SecKeyCopyKeyExchangeResult`.
- **Authenticated Encryption**: Uses Encrypt-then-MAC (AES-256-PKCS7 + HMAC-SHA256) with unique 16-byte random IVs per message.
- **Constant-Time Verification**: Verifies authentication tags using `timingsafe_bcmp` to prevent side-channel timing attacks.
- **Injected File Secret Store (`MNFileSecretStore`)**:
  - Implements `<MNSecretStoring>` for pluggable storage and mock injection in unit tests.
  - Persists secrets to `~/Library/Application Support/MacNexa/secrets.enc` encrypted with AES-256-CBC + HMAC-SHA256.
  - Enforces `0700` POSIX directory permissions and `0600` file permissions on `secrets.seed` and `secrets.enc`.
  - Safely quarantines corrupt files to `secrets.enc.corrupt.<timestamp>` to prevent daemon crashes or infinite error loops.
  - Propagates all storage errors (`NSError`) to the UI via `lastStorageError` and native `NSAlert` dialogs.

### 2.4. Network Engine (`MNNetwork`)
- **Peer Discovery**:
  - Publishes local service `_macnexa._tcp.` on port `57842` via `NSNetService`.
  - Browses for peers via `NSNetServiceBrowser` and resolves IPv4/IPv6 socket addresses.
- **Hardened TCP Server**:
  - Non-blocking socket listener driven by Grand Central Dispatch (`dispatch_source_t`).
  - Socket timeouts: Strict 3-second `SO_RCVTIMEO` and `SO_SNDTIMEO` to prevent connection holding.
  - Length-prefixed binary framing: `[4-byte Big-Endian Length][JSON Envelope]`.
  - Bounded allocation: Rejects any frame specifying a size $> 64\text{ KB}$.
  - Rate limiting: Rejects pairing modal requests spammed faster than 1 per 10 seconds.

---

## 3. Switching Lifecycle & Sequence Diagram

```
Mac A (Initiator)                                            Mac B (Target)
       │                                                            │
       │ 1. User clicks "Switch to Mac B"                           │
       │                                                            │
       │ 2. Disconnect & Unpair Accessories                         │
       │    [dev closeConnection]                                   │
       │    [dev performSelector:@"remove"]                         │
       │                                                            │
       │ 3. Send Authenticated Switch Request                       │
       │    AES-256-Encrypted Payload + HMAC-SHA256 Tag             │
       │───────────────────────────────────────────────────────────>│
       │                                                            │
       │                                            4. Verify Tag & Decrypt
       │                                               timingsafe_bcmp(tag)
       │                                               Check Nonce & Timestamp
       │                                                            │
       │                                            5. Silently Pair & Connect
       │                                               IOBluetoothDevicePair
       │                                               replyUserConfirmation(YES)
       │                                               [dev openConnection]
       │                                                            │
       │ 6. Receive Acknowledgment                                  │
       │<───────────────────────────────────────────────────────────│
       │                                                            │
       │ 7. UI updates: Status -> Ready                             │ 7. UI updates: Status -> Ready
```

---

## 4. Error Handling & Rollback Strategy

1. **Network Disconnect During Switch**:
   - If the remote Mac fails to acknowledge or the TCP connection drops after Mac A releases its accessories, Mac A automatically triggers a **rollback**:
   - Re-acquires and reconnects all released devices locally from its remembered devices cache.
2. **Silent Pairing Failure**:
   - If a peripheral fails to pair within the 5-second handshake window, the switch transaction marks failure and reports error diagnostics in the menu bar.
3. **Cryptographic Validation Failure**:
   - Packets failing HMAC-SHA256 tag validation, exceeding the 30-second timestamp window, or with nonces $\le \text{lastSeenNonce}$ are discarded immediately with no state change.
