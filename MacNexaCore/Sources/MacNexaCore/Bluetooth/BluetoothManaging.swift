import Foundation

/// Abstraction over all Bluetooth operations (spec §8.1). The UI must never
/// touch IOBluetooth directly; it goes through this protocol.
public protocol BluetoothManaging: Sendable {
    /// Enumerate known/paired Magic devices.
    func devices() async throws -> [ManagedDevice]

    /// Current connection state for a device.
    func connectionState(for device: ManagedDevice) async -> DeviceConnectionState

    /// Attempt to connect (open a baseband connection to) a device.
    func connect(_ device: ManagedDevice) async throws

    /// Disconnect (release) a device so another Mac can claim it.
    func disconnect(_ device: ManagedDevice) async throws
}
