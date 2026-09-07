import Foundation
import MacNexaCore

/// Central place to build and inject dependencies. Swaps mock vs. real
/// implementations based on environment (spec §7, coding-standards).
@MainActor
final class DependencyContainer {
    let bluetooth: BluetoothManaging
    let services: AppServices

    init() {
        let useReal = ProcessInfo.processInfo.environment["MACNEXA_USE_IOBLUETOOTH"] == "1"
        let bt: BluetoothManaging = useReal ? IOBluetoothManager() : MockBluetoothManager()
        self.bluetooth = bt
        do {
            self.services = try AppServices(bluetooth: bt, useKeychain: useReal)
        } catch {
            fatalError("Failed to initialize services: \(error)")
        }
    }
}
