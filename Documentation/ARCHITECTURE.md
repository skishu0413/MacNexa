# Architecture

MacNexa separates hardware-independent logic (the `MacNexaCore` Swift
package) from platform integration (the `MacNexa` app target).

- **Bluetooth controls peripherals** — via `BluetoothManaging` (mock + IOBluetooth).
- **Network.framework coordinates Macs** — Bonjour discovery + authenticated sessions (upcoming).
- **CryptoKit establishes trust** — Curve25519 key agreement, HKDF, HMAC signing.
- **Keychain protects secrets** — long-term keys and shared secrets (upcoming store).
- **SwitchCoordinator owns transactions** — driven by `SwitchStateMachine`.
- **RecoveryManager prevents stranded peripherals** — rollback on failure (upcoming).

The core package is fully unit-tested and has no dependency on IOBluetooth,
Network.framework, or SwiftUI, which keeps the critical logic fast to test.
