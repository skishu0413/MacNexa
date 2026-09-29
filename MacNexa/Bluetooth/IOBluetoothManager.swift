import Foundation
import MacNexaCore
#if canImport(IOBluetooth)
import IOBluetooth
#endif
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

/// Helper to trigger macOS system Bluetooth authorization prompt on launch.
private final class BluetoothPermissionHelper: NSObject, CBCentralManagerDelegate, @unchecked Sendable {
    private var central: CBCentralManager?

    override init() {
        super.init()
        central = CBCentralManager(
            delegate: self,
            queue: DispatchQueue(label: "com.macnexa.bluetooth.perm", qos: .utility)
        )
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {}
}

#if canImport(IOBluetooth)
/// Delegate that auto-confirms Secure Simple Pairing (SSP) so the macOS pairing dialog is suppressed.
private final class SilentPairDelegate: NSObject, IOBluetoothDevicePairDelegate, @unchecked Sendable {
    private let continuation: CheckedContinuation<Bool, Never>
    private var finished = false

    init(continuation: CheckedContinuation<Bool, Never>) {
        self.continuation = continuation
        super.init()
    }

    func devicePairingUserConfirmationRequest(_ sender: Any!, numericValue: BluetoothNumericValue) {
        // Auto-confirm numeric comparison so macOS suppresses the system dialog.
        (sender as? IOBluetoothDevicePair)?.replyUserConfirmation(true)
    }

    func devicePairingPINCodeRequest(_ sender: Any!) {
        var pin = BluetoothPINCode()
        (sender as? IOBluetoothDevicePair)?.replyPINCode(0, pinCode: &pin)
    }

    func devicePairingFinished(_ sender: Any!, error: IOReturn) {
        guard !finished else { return }
        finished = true
        continuation.resume(returning: error == kIOReturnSuccess)
    }
}
#endif

/// IOBluetooth-backed manager supporting enumeration, pairing, unpairing, and connection.
public actor IOBluetoothManager: BluetoothManaging, BluetoothMonitoring {
    private let monitor = IOBluetoothMonitor()
    private let permHelper = BluetoothPermissionHelper()
    private let defaultsKey = "com.macnexa.known_devices"
    private var rememberedDevices: [String: ManagedDevice] = [:]

    public init() {
        self.rememberedDevices = Self.loadRememberedDevices(defaultsKey: "com.macnexa.known_devices")
    }

    public func devices() async throws -> [ManagedDevice] {
        #if canImport(IOBluetooth)
        let paired = IOBluetoothDevice.pairedDevices() as? [IOBluetoothDevice] ?? []
        var result: [String: ManagedDevice] = rememberedDevices
        
        for dev in paired {
            if let mapped = Self.map(dev) {
                result[mapped.bluetoothAddress] = mapped
            }
        }
        
        rememberedDevices = result
        Self.saveRememberedDevices(result, defaultsKey: defaultsKey)
        return Array(result.values).sorted { $0.name < $1.name }
        #else
        return Array(rememberedDevices.values)
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

        // 1. If already connected, success.
        if dev.isConnected() { return }

        // 2. If reported as paired, attempt openConnection() directly.
        if dev.isPaired() {
            let result = dev.openConnection()
            if result == kIOReturnSuccess && dev.isConnected() {
                return
            }
        }

        // 3. Device needs pairing (or stale pairing needs renewal after remote unpair).
        let paired = await pairWithDevice(dev)
        if !paired && !dev.isPaired() {
            throw device.type == .trackpad ? SwitchError.trackpadConnectionFailed : SwitchError.keyboardConnectionFailed
        }

        // 4. Open connection after pairing.
        let openResult = dev.openConnection()
        guard openResult == kIOReturnSuccess || dev.isConnected() else {
            throw device.type == .trackpad ? SwitchError.trackpadConnectionFailed : SwitchError.keyboardConnectionFailed
        }
        #else
        throw SwitchError.keyboardConnectionFailed
        #endif
    }

    public func disconnect(_ device: ManagedDevice) async throws {
        #if canImport(IOBluetooth)
        guard let dev = Self.find(address: device.bluetoothAddress) else { return }
        
        // Save to remembered devices before unpairing so we don't forget it when unbonded.
        rememberedDevices[device.bluetoothAddress] = device
        Self.saveRememberedDevices(rememberedDevices, defaultsKey: defaultsKey)

        // Apple Magic devices require unpairing (-remove) so the peripheral resets its host connection
        // and allows the other Mac to bond and connect silently.
        let sel = NSSelectorFromString("remove")
        if dev.responds(to: sel) {
            dev.perform(sel)
        } else {
            _ = dev.closeConnection()
        }
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
    private func pairWithDevice(_ dev: IOBluetoothDevice) async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                guard let pairer = IOBluetoothDevicePair(device: dev) else {
                    continuation.resume(returning: false)
                    return
                }
                let delegate = SilentPairDelegate(continuation: continuation)
                pairer.delegate = delegate
                objc_setAssociatedObject(pairer, "silentPairDelegate", delegate, .OBJC_ASSOCIATION_RETAIN)
                let result = pairer.start()
                if result != kIOReturnSuccess {
                    pairer.stop()
                    continuation.resume(returning: false)
                }
            }
        }
    }

    private static func find(address: String) -> IOBluetoothDevice? {
        IOBluetoothDevice(addressString: address)
    }

    private static func map(_ device: IOBluetoothDevice) -> ManagedDevice? {
        let name = device.name ?? "Unknown"
        guard let address = device.addressString else { return nil }
        let type = classify(name: name)
        guard type != .unknown else { return nil }
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

    // MARK: Persistence Helpers
    private static func loadRememberedDevices(defaultsKey: String) -> [String: ManagedDevice] {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let list = try? JSONDecoder().decode([ManagedDevice].self, from: data) else {
            return [:]
        }
        return Dictionary(uniqueKeysWithValues: list.map { ($0.bluetoothAddress, $0) })
    }

    private static func saveRememberedDevices(_ devices: [String: ManagedDevice], defaultsKey: String) {
        if let data = try? JSONEncoder().encode(Array(devices.values)) {
            UserDefaults.standard.set(data, forKey: defaultsKey)
        }
    }
}
