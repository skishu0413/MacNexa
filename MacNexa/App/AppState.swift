import Foundation
import SwiftUI
import MacNexaCore

/// Observable UI-facing application state (spec §26, §35). Talks only to the
/// manager abstractions and services, never to IOBluetooth/Network directly.
@MainActor
final class AppState: ObservableObject {
    @Published private(set) var thisMacName: String
    @Published private(set) var deviceStatuses: [DeviceStatus] = []
    @Published private(set) var peers: [Peer] = []
    @Published private(set) var isSwitching = false
    @Published private(set) var bluetoothAvailable = true
    @Published var lastError: String?
    @Published var pendingPairing: PendingPairing?
    @Published var launchAtLogin: Bool {
        didSet { services.setLaunchAtLogin(launchAtLogin) }
    }

    private let bluetooth: BluetoothManaging
    private let services: AppServices

    init(bluetooth: BluetoothManaging, services: AppServices) {
        self.bluetooth = bluetooth
        self.services = services
        self.thisMacName = services.thisMacName
        self.launchAtLogin = services.isLaunchAtLoginEnabled
        services.onPendingPairing = { [weak self] pending in
            self?.pendingPairing = pending
        }
    }

    func start() async {
        await refreshDevices()
        // Live Bluetooth monitoring (spec §35): update UI without polling.
        services.startBluetoothMonitoring { [weak self] event in
            Task { @MainActor in self?.apply(event) }
        }
        services.startDiscovery { [weak self] discovered in
            Task { @MainActor in self?.peers = discovered }
        }
    }

    private func apply(_ event: BluetoothEvent) {
        switch event {
        case .deviceConnected(let id):
            updateState(id, to: .connected)
        case .deviceDisconnected(let id):
            updateState(id, to: .disconnected)
        case .bluetoothUnavailable:
            bluetoothAvailable = false
        case .bluetoothRestored:
            bluetoothAvailable = true
            Task { await refreshDevices() }
        }
    }

    private func updateState(_ id: UUID, to state: DeviceConnectionState) {
        guard let idx = deviceStatuses.firstIndex(where: { $0.device.id == id }) else { return }
        deviceStatuses[idx] = DeviceStatus(device: deviceStatuses[idx].device, state: state)
    }

    func refreshDevices() async {
        do {
            let devices = try await bluetooth.devices()
            var statuses: [DeviceStatus] = []
            for device in devices {
                let state = await bluetooth.connectionState(for: device)
                statuses.append(DeviceStatus(device: device, state: state))
            }
            deviceStatuses = statuses
        } catch {
            lastError = "Failed to read Bluetooth devices"
            Log.bluetooth.error("device refresh failed: \(String(describing: error), privacy: .public)")
        }
    }

    func switchTo(peer: Peer) async {
        guard !isSwitching else { return }
        isSwitching = true
        defer { isSwitching = false }
        do {
            try await services.performSwitch(devices: deviceStatuses.map(\.device), toPeer: peer)
            await refreshDevices()
        } catch {
            lastError = Self.describe(error)
            Log.switching.error("switch failed: \(String(describing: error), privacy: .public)")
        }
    }

    func beginPairing(with peer: Peer) {
        services.beginPairing(withPeerNamed: peer.displayName)
    }

    func confirmPairing() {
        guard let pending = pendingPairing else { return }
        services.confirmPairing(pending)
        pendingPairing = nil
        Task { await refreshDevices() }
    }

    func cancelPairing() { pendingPairing = nil }

    func trustedPeers() -> [TrustedPeer] { services.trustedPeers() }
    func revokeTrust(_ id: UUID) { services.revokeTrust(id) }

    private static func describe(_ error: Error) -> String {
        guard let e = error as? SwitchError else { return "Switch failed" }
        switch e {
        case .peerUnavailable: return "The other Mac is unavailable or not paired."
        case .releaseTimedOut, .releaseRejected: return "The other Mac did not release the devices."
        case .keyboardConnectionFailed: return "Could not connect the keyboard."
        case .trackpadConnectionFailed: return "Could not connect the trackpad."
        case .verificationFailed: return "Devices did not verify after switching."
        case .transactionConflict: return "A switch is already in progress."
        default: return "Switch failed and was rolled back."
        }
    }
}
