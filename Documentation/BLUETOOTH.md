# Bluetooth

The Bluetooth layer is hidden behind `BluetoothManaging`. Two implementations:

- `MockBluetoothManager` (in core) — in-memory, for development and tests.
- `IOBluetoothManager` (in app) — backed by IOBluetooth.

The largest technical risk (spec §49) is reliable Magic Keyboard/Trackpad
release and reconnect. This must be validated on real hardware (Phase 1/2)
before investing in networking/UI. The IOBluetooth connect/disconnect paths
are the feasibility gate.

## Hardware validation results

Validated on a physical Mac (macOS 26) with a Magic Keyboard and Magic Trackpad.

Phase 1 (§33) — enumeration & classification: **PASS**
- Paired devices enumerated correctly.
- Magic Keyboard and Magic Trackpad classified correctly; non-Magic devices
  (AirPods, iPad) correctly ignored.
- Live connection state read correctly.

Phase 2 (§34, §49) — disconnect/reconnect: **PASS**
- Magic Trackpad: `closeConnection()` → disconnected, `openConnection()` →
  reconnected on the first attempt. This retires the project's #1 technical risk.

### Diagnostic tool

`Tools/MacNexaProbe` is a read-only/controlled CLI for validating the
IOBluetooth path independently of the UI:

```bash
cd Tools/MacNexaProbe
swift run                          # enumerate + classify (safe, read-only)
swift run MacNexaProbe cycle <bluetooth-address>   # disconnect + reconnect one device
```

The same IOBluetooth APIs (`pairedDevices`, `isConnected`, `openConnection`,
`closeConnection`) back `IOBluetoothManager` in the app.
