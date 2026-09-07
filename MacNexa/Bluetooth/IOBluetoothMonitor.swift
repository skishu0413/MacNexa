import Foundation
import MacNexaCore
#if canImport(IOBluetooth)
import IOBluetooth
#endif

/// Observes IOBluetooth connection notifications and forwards them as
/// `BluetoothEvent`s (spec §35). Uses IOBluetooth's global connect notification;
/// per-device disconnect notifications are registered as devices connect.
final class IOBluetoothMonitor: NSObject, @unchecked Sendable {
    private var handler: (@Sendable (BluetoothEvent) -> Void)?
    #if canImport(IOBluetooth)
    private var connectNotification: IOBluetoothUserNotification?
    private var disconnectNotifications: [IOBluetoothUserNotification] = []
    #endif

    func start(_ handler: @escaping @Sendable (BluetoothEvent) -> Void) {
        self.handler = handler
        #if canImport(IOBluetooth)
        // Global notification when any device connects.
        connectNotification = IOBluetoothDevice.register(
            forConnectNotifications: self,
            selector: #selector(deviceConnected(_:device:))
        )
        #endif
    }

    func stop() {
        #if canImport(IOBluetooth)
        connectNotification?.unregister()
        connectNotification = nil
        disconnectNotifications.forEach { $0.unregister() }
        disconnectNotifications.removeAll()
        #endif
        handler = nil
    }

    #if canImport(IOBluetooth)
    @objc private func deviceConnected(_ notification: IOBluetoothUserNotification, device: IOBluetoothDevice) {
        guard let id = Self.id(for: device) else { return }
        handler?(.deviceConnected(id))
        // Register for this device's disconnection.
        let disconnect = device.register(
            forDisconnectNotification: self,
            selector: #selector(deviceDisconnected(_:device:))
        )
        if let disconnect { disconnectNotifications.append(disconnect) }
    }

    @objc private func deviceDisconnected(_ notification: IOBluetoothUserNotification, device: IOBluetoothDevice) {
        notification.unregister()
        guard let id = Self.id(for: device) else { return }
        handler?(.deviceDisconnected(id))
    }

    /// Derives a stable UUID from the device address so events correlate with
    /// enumerated `ManagedDevice`s.
    private static func id(for device: IOBluetoothDevice) -> UUID? {
        guard let address = device.addressString else { return nil }
        return DeviceIdentity.uuid(forAddress: address)
    }
    #endif
}
