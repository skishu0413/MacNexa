# MacNexa ⌨️

[![macOS](https://img.shields.io/badge/macOS-12%20%7C%2013%20%7C%2014%20%7C%2015%20%7C%2016%2B-blue.svg?style=flat-square&logo=apple)](https://apple.com)
[![Build](https://img.shields.io/badge/build-1--command%20(%3C3s)-success.svg?style=flat-square)](https://github.com/skishu0413/MacNexa)
[![Security](https://img.shields.io/badge/security-Zero--Trust%20%7C%20ECDH%20%7C%20AES--256-orange.svg?style=flat-square)](Documentation/SECURITY.md)
[![Dependencies](https://img.shields.io/badge/dependencies-Zero%20(No%20Xcode%20Req)-brightgreen.svg?style=flat-square)](#quick-start-single-command)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg?style=flat-square)](LICENSE)

**MacNexa** is a high-performance, native macOS menu-bar utility designed for instant, wireless handoff of Apple Magic accessories (**Magic Keyboard**, **Magic Trackpad**, and **Magic Mouse**) between multiple Macs over your local network — engineered with **military-grade Zero-Trust cryptographic security**.

Unlike existing solutions that rely on insecure cleartext communication or require complex manual Bluetooth settings, MacNexa provides a **seamless 1-click handoff** with silent pairing, real-time accessory battery monitoring, and mutual cryptographic authentication.

---

## Key Features

- **Instant 1-Click Handoff**: Switch your Magic Keyboard and Trackpad between your MacBook and Mac Mini with a single click or keyboard shortcut.
- **Silent Bluetooth Pairing**: Uses private Apple IOBluetooth handoff APIs to disconnect and silently pair peripherals without annoying system confirmation dialogs.
- **Real-Time Battery Percentage**: Displays live battery levels with battery health indicators (`🔋 85%`, `🪫 18% Low`) directly in your menu bar.
- **Zero-Trust Mutual Security**:
  - **ECDH (P-256) Key Exchange**: Master keys are negotiated securely and **never cross the network**.
  - **6-Digit SAS Visual Verification**: Prevents Man-in-the-Middle (MitM) attacks during initial pairing.
  - **Encrypt-then-MAC (AES-256 + HMAC-SHA256)**: All commands are fully encrypted and signed with constant-time verification.
  - **Hardware Keychain Storage**: Shared secrets are locked inside Apple's hardware-encrypted macOS Keychain.
  - **Anti-Replay & DoS Protection**: Monotonically increasing sequence nonces, timestamp drift limits, and socket timeouts.
- **Universal Multi-Version Compatibility**: Works across **all** macOS releases (macOS 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia, 16+ Tahoe). Cross-compatible across mixed versions (Old-to-New, New-to-Old).
- **Zero Heavy Dependencies**: Builds and runs in **under 3 seconds** using Apple's built-in Command Line Tools (`clang`). **No 15 GB Xcode download required.**
- **100% Offline & Private**: Zero cloud dependency, zero telemetry, zero analytics. Runs exclusively on your local Wi-Fi / Ethernet network.

---

## Architecture at a Glance

```
 ┌────────────────────────────────────────────────────────┐
 │                      macOS Menu Bar                    │
 │               [ ⌨️  MacNexa Menu Controller ]          │
 └──────────────────────────┬─────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
 ┌──────────────────────┐       ┌──────────────────────┐
 │  MNBluetoothManager  │       │      MNNetwork       │
 │──────────────────────│       │──────────────────────│
 │ • IOBluetooth Engine │       │ • Bonjour Discovery  │
 │ • Silent Auto-Pair   │       │ • BSD Socket Server  │
 │ • Unpair via remove  │       │ • DoS Protected I/O  │
 │ • IOKit Battery Mon  │       │ • Port: 57842        │
 └──────────┬───────────┘       └──────────┬───────────┘
            │                              │
            │                   ┌──────────┴───────────┐
            │                   │      MNSecurity      │
            │                   │──────────────────────│
            │                   │ • ECDH (P-256)       │
            │                   │ • 6-Digit SAS Code   │
            │                   │ • AES-256 Encryption │
            │                   │ • HMAC-SHA256 EtM    │
            │                   │ • macOS Keychain     │
            │                   └──────────────────────┘
            ▼                               │
 ┌──────────────────────┐                   ▼
 │   Apple Peripherals  │        Encrypted Local Network
 │  Keyboard & Trackpad │    ===============================> Remote Mac
 └──────────────────────┘
```

---

## Quick Start (Single Command)

To build, sign, and launch MacNexa in one command, open Terminal in the repository root and run:

```bash
./run.sh
```
*(Or simply run `make`)*

### What happens automatically:
1. Verifies your macOS build environment.
2. Compiles the native engine in **~2 seconds** using `clang`.
3. Packages `MacNexa.app` and ad-hoc signs it with Bluetooth and Local Network entitlements.
4. Closes any stale background instance and launches the new build directly into your menu bar.

---

## Setup & Pairing Workflow

To connect and switch between your **MacBook** and **Mac Mini**:

### Step 1: Launch on Both Macs
Run `./run.sh` on both machines. Look for the **keyboard icon (`⌨️`)** in the macOS menu bar at the top right of your screen.

### Step 2: Mutual Security Pairing (One-Time)
1. On either Mac, click the **`⌨️`** menu bar icon and select **`Pair New Mac ▸`**.
2. Select your other Mac from the list of auto-discovered peers.
3. A security verification modal will appear on **both** screens:
   ```text
   MacNexa Security Verification
   Pairing request from: Mac Mini

   Do the 6 digits match on both screens?
            [  849 201  ]
   ```
4. Confirm the codes match and click **Confirm & Trust** on both computers.
5. Both Macs establish a mutually authenticated cryptographic trust relationship stored securely in the **macOS Keychain**.

### Step 3: Switch Peripherals!
Click the menu bar icon and click **`🔄 Switch to <Mac Name>`**.
- The current Mac releases and unpairs the accessories locally.
- The remote Mac silently connects and acquires the keyboard and trackpad in seconds.

---

## Menu Bar Controls

Clicking the **`⌨️`** icon in your menu bar opens the control dashboard:

```text
MacNexa: Ready
────────────────────────────────────────────
Accessories (2 active):
  ⌨️ Suraj’s Magic Keyboard   🔋 88%
  🖱️ Suraj Khadka’s Trackpad  🔋 94%
  ⚡ Connect / Reconnect Accessories
────────────────────────────────────────────
Switch to:
  🔄 Switch to Mac Mini (Online)
Pair New Mac ▸
Refresh Devices & Network
Quit MacNexa
```

---

## Command Line Reference

| Command | Action | Description |
| :--- | :--- | :--- |
| `./run.sh` *(or `make`)* | **Build & Launch** | Compiles, signs, and launches MacNexa with real Bluetooth hardware. |
| `./run.sh --mock` *(or `make mock`)* | **Simulated Mode** | Launches with simulated peripherals (ideal for development without hardware disconnects). |
| `./run.sh --logs` *(or `make logs`)* | **Stream Logs** | Streams real-time unified logs and connection diagnostics to console. |
| `./run.sh --clean` *(or `make clean`)* | **Clean Build** | Cleans build cache and artifacts. |
| `killall MacNexa` | **Stop App** | Immediately stops the running background application. |

---

## Security Architecture

MacNexa is designed with a **Zero-Trust security model** to prevent unauthorized access or device hijacking on untrusted or shared local networks (e.g. coffee shops, shared apartments, office networks).

| Threat Vector | Standard Apps | MacNexa Defense |
| :--- | :--- | :--- |
| **Wi-Fi Eavesdropping** | Cleartext JSON secrets over TCP. | **Ephemeral ECDH (P-256)**: Master secret is never transmitted. Payloads encrypted with **AES-256**. |
| **Man-in-the-Middle (MitM)** | Auto-accepts connections silently. | **Visual 6-Digit SAS Confirmation**: Users visually match codes derived from cryptographic key agreements. |
| **Packet Replay Attacks** | Replaying captured packets triggers disconnects. | **Strict Monotonic Nonces & 30s Skew Windows**: Replayed or expired packets are rejected immediately. |
| **Payload Tampering** | Weak checksums or missing signatures. | **Encrypt-then-MAC (EtM)**: HMAC-SHA256 verified in constant time (`timingsafe_bcmp`) before decryption. |
| **Key Theft by Malware** | Secrets stored in plaintext `.plist` files. | **Hardware macOS Keychain**: Stored using `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. |
| **Network Denial of Service (DoS)** | Unbounded buffers & hung connections. | **64 KB Frame Cap + 3s Socket Timeouts + 10s Rate Limiting**. |

*For complete cryptographic proofs and implementation details, see [Documentation/SECURITY.md](Documentation/SECURITY.md).*

---

## Project Structure

```text
MacNexa/
├── run.sh                          # Universal 1-command build, sign, and runner script
├── Makefile                        # Convenience make runner (make, make mock, make logs)
├── MacNexa/
│   ├── Native/                     # Universal Native Engine (macOS 12+ / 13 / 14 / 15 / 16+)
│   │   ├── main.m                  # App entry point (LSUIElement daemon)
│   │   ├── MNMenuController.{h,m}  # Status bar UI & modal alert presenter
│   │   ├── MNBluetoothManager.{h,m}# IOBluetooth & IOKit battery monitoring engine
│   │   ├── MNNetwork.{h,m}         # Bonjour discovery & hardened TCP server
│   │   └── MNSecurity.{h,m}        # ECDH, Keychain, AES-256 & HMAC cryptography
│   ├── Resources/
│   │   ├── Info.plist              # Bundle metadata & usage descriptions
│   │   └── MacNexa-Debug.entitlements # Hardware Bluetooth & network entitlements
│   └── App/                        # Optional SwiftUI App Target
├── MacNexaCore/                    # Pure Swift Core Protocol & Switch Coordinator
├── Documentation/                  # In-depth architectural & security specifications
│   ├── SECURITY.md                 # Complete threat model & cryptographic specifications
│   ├── ARCHITECTURE.md             # Subsystem interactions & lifecycle details
│   ├── PROTOCOL.md                 # Network wire protocol & frame specification
│   ├── BLUETOOTH.md                # IOBluetooth internal SPI & device pairing behavior
│   └── DEVELOPMENT.md              # Contributor guidelines & testing patterns
└── project.yml                     # Optional XcodeGen project definition
```

---

## Compatibility

- **macOS Versions**: Compatible with macOS 12 (Monterey), 13 (Ventura), 14 (Sonoma), 15 (Sequoia), and 16+ (Tahoe).
- **Supported Hardware**:
  - Apple Magic Keyboard (all generations, with/without Touch ID or Numeric Keypad)
  - Apple Magic Trackpad (all generations)
  - Apple Magic Mouse (all generations)
- **Networking**: Any local Wi-Fi or Ethernet network (supports mixed networks, e.g. Wi-Fi to Ethernet).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
