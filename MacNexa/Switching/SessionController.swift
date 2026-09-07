import Foundation
import MacNexaCore

/// Handles inbound commands on an established, trusted session (spec §19, §39).
///
/// When THIS Mac is the source (currently holding the devices), the peer asks it
/// to RELEASE_DEVICES; this controller disconnects them and replies
/// DEVICES_RELEASED. It also forwards confirmation replies to the local
/// `NetworkPeerControl` so the coordinator's awaits resolve.
final class SessionController: PeerSessionDelegate, @unchecked Sendable {
    private let bluetooth: BluetoothManaging
    private let session: PeerSession
    private let control: NetworkPeerControl
    private let knownDevices: () async -> [ManagedDevice]

    init(bluetooth: BluetoothManaging, session: PeerSession, control: NetworkPeerControl,
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
            await handleReconnect(message)
        case .devicesReleased, .devicesConnected:
            await control.handleConfirmation(message.type, transactionId: message.transactionId)
        case .switchComplete, .switchFailed:
            Log.switching.info("peer reported \(message.type.rawValue, privacy: .public)")
        default:
            break
        }
    }

    private func handleRelease(_ message: NetworkMessage) async {
        // Disconnect the requested devices, then confirm.
        let ids = (try? JSONDecoder().decode(DeviceListPayload.self, from: message.payload))?.deviceIds ?? []
        let devices = await knownDevices().filter { ids.contains($0.id) }
        for device in devices { try? await bluetooth.disconnect(device) }
        try? await session.send(type: .devicesReleased, transactionId: message.transactionId)
    }

    private func handleReconnect(_ message: NetworkMessage) async {
        // Rollback path: source reconnects its devices and confirms.
        let devices = await knownDevices()
        for device in devices { try? await bluetooth.connect(device) }
        try? await session.send(type: .devicesConnected, transactionId: message.transactionId)
    }

    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async {}
    func sessionDidClose(_ session: PeerSession) async {}
}
