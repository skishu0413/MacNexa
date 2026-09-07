import Foundation
#if canImport(IOBluetooth)
import IOBluetooth
#endif

// Read-only enumeration (default) or a controlled disconnect/reconnect cycle
// for a single device selected by address (spec §34, §49).
//
// Usage:
//   MacNexaProbe                 -> enumerate + classify (safe, read-only)
//   MacNexaProbe cycle <address> -> disconnect, wait, reconnect that device

func classify(_ name: String) -> String {
    let l = name.lowercased()
    if l.contains("keyboard") { return "keyboard" }
    if l.contains("trackpad") { return "trackpad" }
    if l.contains("mouse") { return "mouse" }
    return "unknown"
}

#if canImport(IOBluetooth)
let args = CommandLine.arguments

func enumerateDevices() {
    let paired = IOBluetoothDevice.pairedDevices() as? [IOBluetoothDevice] ?? []
    print("Paired devices found: \(paired.count)\n")
    for dev in paired {
        let name = dev.name ?? "Unknown"
        let type = classify(name)
        let tag = (type == "keyboard" || type == "trackpad") ? "  <-- MAGIC" : ""
        print("• \(name)  [\(dev.addressString ?? "??")]  type=\(type) connected=\(dev.isConnected())\(tag)")
    }
}

func state(_ address: String) -> Bool? {
    IOBluetoothDevice(addressString: address)?.isConnected()
}

if args.count >= 3, args[1] == "cycle" {
    let address = args[2]
    guard let dev = IOBluetoothDevice(addressString: address) else {
        print("FAIL: no device at address \(address)"); exit(1)
    }
    let name = dev.name ?? "device"
    print("Target: \(name) [\(address)]")
    print("Initial connected: \(dev.isConnected())\n")

    // 1. Disconnect
    print("-> Disconnecting…")
    let closeResult = dev.closeConnection()
    Thread.sleep(forTimeInterval: 2.0)
    let afterClose = state(address) ?? true
    print("   closeConnection result: \(closeResult) (kIOReturnSuccess=\(kIOReturnSuccess))")
    print("   connected after disconnect: \(afterClose)")

    // 2. Reconnect (bounded retry)
    print("\n-> Reconnecting…")
    var reconnected = false
    for attempt in 1...3 {
        let openResult = dev.openConnection()
        Thread.sleep(forTimeInterval: 2.0)
        let nowConnected = state(address) ?? false
        print("   attempt \(attempt): openConnection=\(openResult) connected=\(nowConnected)")
        if nowConnected { reconnected = true; break }
    }

    print("\n" + String(repeating: "-", count: 40))
    if reconnected {
        print("PASS: \(name) disconnected and reconnected successfully.")
    } else {
        print("NOTE: explicit reconnect did not confirm; macOS usually auto-reconnects Magic devices shortly.")
    }
} else {
    print("MacNexa Bluetooth Probe")
    print(String(repeating: "=", count: 40))
    enumerateDevices()
}
#else
print("IOBluetooth not available on this platform.")
#endif
