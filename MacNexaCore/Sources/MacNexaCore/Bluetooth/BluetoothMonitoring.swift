import Foundation

/// A Bluetooth state-change event observed by the monitor (spec §35).
public enum BluetoothEvent: Sendable, Equatable {
    case deviceConnected(UUID)
    case deviceDisconnected(UUID)
    case bluetoothUnavailable
    case bluetoothRestored
}

/// Observes Bluetooth state changes so the UI updates without polling (spec §35).
/// The real implementation is IOBluetooth-notification-backed; the mock emits
/// programmatic events for tests and demos.
public protocol BluetoothMonitoring: Sendable {
    /// Begins delivering events to the handler. Idempotent.
    func startMonitoring(_ handler: @escaping @Sendable (BluetoothEvent) -> Void) async
    func stopMonitoring() async
}
