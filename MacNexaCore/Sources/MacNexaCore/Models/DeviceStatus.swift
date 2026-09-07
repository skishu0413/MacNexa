import Foundation

/// Volatile connection state of a peripheral. Kept separate from identity.
public enum DeviceConnectionState: String, Codable, Sendable {
    case connected
    case disconnected
    case connecting
    case error
}

/// A snapshot pairing a device identity with its current connection state.
public struct DeviceStatus: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID { device.id }
    public let device: ManagedDevice
    public let state: DeviceConnectionState

    public init(device: ManagedDevice, state: DeviceConnectionState) {
        self.device = device
        self.state = state
    }
}
