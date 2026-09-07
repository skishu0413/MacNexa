import Foundation

/// In-memory Bluetooth manager used for development on machines without the
/// target peripherals, and for integration testing (spec §45). Also emits
/// monitoring events when device state changes (spec §35).
public actor MockBluetoothManager: BluetoothManaging, BluetoothMonitoring {
    private var known: [ManagedDevice]
    private var states: [UUID: DeviceConnectionState]
    private var eventHandler: (@Sendable (BluetoothEvent) -> Void)?

    public init(devices: [ManagedDevice] = MockBluetoothManager.sampleDevices) {
        self.known = devices
        self.states = Dictionary(uniqueKeysWithValues: devices.map { ($0.id, .connected) })
    }

    public func devices() async throws -> [ManagedDevice] { known }

    public func connectionState(for device: ManagedDevice) async -> DeviceConnectionState {
        states[device.id] ?? .disconnected
    }

    public func connect(_ device: ManagedDevice) async throws {
        states[device.id] = .connected
        eventHandler?(.deviceConnected(device.id))
    }

    public func disconnect(_ device: ManagedDevice) async throws {
        states[device.id] = .disconnected
        eventHandler?(.deviceDisconnected(device.id))
    }

    // MARK: BluetoothMonitoring

    public func startMonitoring(_ handler: @escaping @Sendable (BluetoothEvent) -> Void) async {
        eventHandler = handler
    }

    public func stopMonitoring() async {
        eventHandler = nil
    }

    /// Test/demo helper to simulate an external state change.
    public func simulate(_ event: BluetoothEvent) {
        eventHandler?(event)
    }

    public static let sampleDevices: [ManagedDevice] = [
        ManagedDevice(bluetoothAddress: "AA-BB-CC-00-00-01", name: "Magic Keyboard", type: .keyboard),
        ManagedDevice(bluetoothAddress: "AA-BB-CC-00-00-02", name: "Magic Trackpad", type: .trackpad)
    ]
}
