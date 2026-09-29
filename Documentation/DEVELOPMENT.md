# MacNexa Developer Guide

This document outlines local development workflows, testing patterns, and architectural conventions for contributors and developers working on MacNexa.

---

## 1. Fast Development Workflow

MacNexa is designed for **instant build iterations** (<3 seconds) without requiring heavy IDEs or multi-step toolchains.

### Quick Commands

```bash
# 1. Build & run live app (real Bluetooth hardware):
./run.sh

# 2. Build & run with simulated peripherals (ideal for UI / network testing):
./run.sh --mock

# 3. Stream live console logs and connection events:
./run.sh --logs

# 4. Clean build artifacts:
./run.sh --clean

# 5. Stop running background app:
killall MacNexa
```

*(You can also simply type `make`, `make mock`, `make logs`, or `make clean`)*

---

## 2. Directory Structure & Code Organization

- **`MacNexa/Native/`**:
  - `main.m`: Daemon entry point (`LSUIElement = true`).
  - `MNMenuController.{h,m}`: Menu-bar UI, status updates, and `NSAlert` modal presentation.
  - `MNBluetoothManager.{h,m}`: IOBluetooth peripheral discovery, unpairing, silent pairing, and IOKit battery monitoring.
  - `MNNetwork.{h,m}`: Bonjour service advertisement/discovery, socket I/O, frame parsing, and DoS protections.
  - `MNSecurity.{h,m}`: NIST P-256 ECDH key exchange, SAS calculation, AES-256 + HMAC-SHA256 Encrypt-then-MAC, and macOS Keychain integration.
- **`MacNexaCore/`**:
  - Pure Swift library containing protocol definitions, replay protection, state machines, and unit tests.
- **`Documentation/`**:
  - Comprehensive documentation covering architecture, security, protocol, and hardware details.

---

## 3. Testing Patterns

### 3.1. Simulated / Mock Testing
When testing on a single machine or without physical Apple accessories nearby, run:
```bash
./run.sh --mock
```
In mock mode:
- Peripherals (`Mock Magic Keyboard 🔋 88%` and `Mock Magic Trackpad 🔋 94%`) are simulated in memory.
- Network pairing and switching can be executed without disconnecting real hardware.

### 3.2. Core Unit Tests
To run unit tests in `MacNexaCore`:
```bash
cd MacNexaCore && swift test
```

---

## 4. Coding & Security Conventions

1. **Memory Safety & Constant-Time Comparisons**:
   - Always compare cryptographic tags and signatures using `timingsafe_bcmp` to prevent side-channel timing attacks.
2. **Fail-Closed Networking**:
   - Every inbound packet must pass signature, nonce, and timestamp validation before any device state is modified.
   - Any frame exceeding 64 KB or failing validation is dropped immediately.
3. **Hardware Storage**:
   - Never write shared secrets, master keys, or private keys to `NSUserDefaults` or log statements. Use macOS Keychain (`kSecClassGenericPassword`).
