import Foundation
import MacNexaCore
#if canImport(IOBluetooth)
import IOBluetooth
#endif

/// IOBluetooth-backed implementation (spec §6, §33-35).
///
/// NOTE: The actual release/reconnect behavior of Magic peripherals is the
/// project's largest technical risk (spec §49) and must be validated on real
/// hardware. This implementation provides enumeration, connection state,
/// connect/disconnect, and event monitoring.
public actor IOBluetoothManager: BluetoothManaging, BluetoothMonitoring {
    private let monitor = IOBluetoothMonitor()

    public init() {}

    public func devices() async throws -> [ManagedDevice] {
        #if canImport(IOBluetooth)
        let paired = IOBluetoothDevice.pairedDevices() as? [IOBluetoothDevice] ?? []
        return paired.compactMap { Self.map($0) }
        #else
        return []
        #endif
    }

    public func connectionState(for device: ManagedDevice) async -> DeviceConnectionState {
        #if canImport(IOBluetooth)
        guard let dev = Self.find(address: device.bluetoothAddress) else { return .disconnected }
        return dev.isConnected() ? .connected : .disconnected
        #else
        return .disconnected
        #endif
    }

    public func connect(_ device: ManagedDevice) async throws {
        #if canImport(IOBluetooth)
        guard let dev = Self.find(address: device.bluetoothAddress) else {
            throw device.type == .trackpad ? SwitchError.trackpadConnectionFailed : SwitchError.keyboardConnectionFailed
        }
        let result = dev.openConnection()
        guard result == kIOReturnSuccess else {
            throw device.type == .trackpad ? SwitchError.trackpadConnectionFailed : SwitchError.keyboardConnectionFailed
        }
        #else
        throw SwitchError.keyboardConnectionFailed
        #endif
    }

    public func disconnect(_ device: ManagedDevice) async throws {
        #if canImport(IOBluetooth)
        guard let dev = Self.find(address: device.bluetoothAddress) else { return }
        _ = dev.closeConnection()
        #endif
    }

    // MARK: BluetoothMonitoring

    public func startMonitoring(_ handler: @escaping @Sendable (BluetoothEvent) -> Void) async {
        monitor.start(handler)
    }

    public func stopMonitoring() async {
        monitor.stop()
    }

    #if canImport(IOBluetooth)
    private static func find(address: String) -> IOBluetoothDevice? {
        IOBluetoothDevice(addressString: address)
    }

    private static func map(_ device: IOBluetoothDevice) -> ManagedDevice? {
        let name = device.name ?? "Unknown"
        guard let address = device.addressString else { return nil }
        let type = classify(name: name)
        guard type != .unknown else { return nil }
        // Stable id derived from address so events correlate with this device.
        return ManagedDevice(id: DeviceIdentity.uuid(forAddress: address),
                             bluetoothAddress: address, name: name, type: type)
    }

    private static func classify(name: String) -> DeviceType {
        let lower = name.lowercased()
        if lower.contains("keyboard") { return .keyboard }
        if lower.contains("trackpad") { return .trackpad }
        if lower.contains("mouse") { return .mouse }
        return .unknown
    }
    #endif
}
