import Foundation
import MacNexaCore

/// Handles inbound commands on an established, trusted session (spec §19, §39).
///
/// When THIS Mac is the source (currently holding the devices), the peer asks it
/// to RELEASE_DEVICES; this controller disconnects them and replies
/// DEVICES_RELEASED. When THIS Mac is the target, it receives CONNECT_DEVICES and connects them.
/// It also forwards confirmation replies to the local `NetworkPeerControl` so the coordinator's awaits resolve.
final class SessionController: PeerSessionDelegate, @unchecked Sendable {
    private let bluetooth: BluetoothManaging
    private let session: PeerSession
    private let control: NetworkPeerControl?
    private let knownDevices: () async -> [ManagedDevice]
    var onSwitchCompleted: (@Sendable () -> Void)?

    init(bluetooth: BluetoothManaging, session: PeerSession, control: NetworkPeerControl? = nil,
         knownDevices: @escaping () async -> [ManagedDevice]) {
        self.bluetooth = bluetooth
        self.session = session
        self.control = control
        self.knownDevices = knownDevices
    }

    func session(_ session: PeerSession, didReceive message: NetworkMessage, from peer: TrustedPeer) async {
        switch message.type {
        case .releaseDevices:
            await handleRelease(message)
        case .connectDevices:
            await handleConnect(message)
        case .devicesReleased, .devicesConnected:
            await control?.handleConfirmation(message.type, transactionId: message.transactionId)
        case .switchComplete:
            Log.switching.info("peer reported switchComplete")
            onSwitchCompleted?()
        case .switchFailed:
            Log.switching.info("peer reported switchFailed")
        default:
            break
        }
    }

    private func handleRelease(_ message: NetworkMessage) async {
        let payload = try? JSONDecoder().decode(DeviceListPayload.self, from: message.payload)
        let ids = payload?.deviceIds ?? []
        let payloadDevices = payload?.devices ?? []
        
        let allKnown = await knownDevices()
        var targetDevices: [ManagedDevice] = payloadDevices
        for dev in allKnown where ids.contains(dev.id) && !targetDevices.contains(where: { $0.id == dev.id }) {
            targetDevices.append(dev)
        }
        if targetDevices.isEmpty {
            targetDevices = allKnown
        }

        for device in targetDevices { 
            try? await bluetooth.disconnect(device) 
        }
        try? await session.send(type: .devicesReleased, transactionId: message.transactionId)
    }

    private func handleConnect(_ message: NetworkMessage) async {
        let payload = try? JSONDecoder().decode(DeviceListPayload.self, from: message.payload)
        let ids = payload?.deviceIds ?? []
        let payloadDevices = payload?.devices ?? []
        
        let allKnown = await knownDevices()
        var targetDevices: [ManagedDevice] = payloadDevices
        for dev in allKnown where ids.contains(dev.id) && !targetDevices.contains(where: { $0.id == dev.id }) {
            targetDevices.append(dev)
        }
        if targetDevices.isEmpty {
            targetDevices = allKnown
        }

        for device in targetDevices { 
            try? await bluetooth.connect(device) 
        }
        try? await session.send(type: .devicesConnected, transactionId: message.transactionId)
    }

    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async {}
    func sessionDidClose(_ session: PeerSession) async {}
}
