import Foundation

/// The persistent identity of a Bluetooth peripheral managed by MacNexa.
///
/// Runtime connection state is intentionally kept separate (see `DeviceStatus`)
/// so that persisted identity does not carry volatile state. The `id` is derived
/// deterministically from the Bluetooth address so it is stable across launches
/// and correlates with monitoring events (spec §9, §35).
public struct ManagedDevice: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    /// Bluetooth hardware address, e.g. "AA-BB-CC-DD-EE-FF".
    public let bluetoothAddress: String
    public let name: String
    public let type: DeviceType

    /// Creates a device with an explicit id (used by tests/fixtures).
    public init(id: UUID, bluetoothAddress: String, name: String, type: DeviceType) {
        self.id = id
        self.bluetoothAddress = bluetoothAddress
        self.name = name
        self.type = type
    }

    /// Creates a device whose id is derived deterministically from the address.
    public init(bluetoothAddress: String, name: String, type: DeviceType) {
        self.id = DeviceIdentity.uuid(forAddress: bluetoothAddress)
        self.bluetoothAddress = bluetoothAddress
        self.name = name
        self.type = type
    }
}
