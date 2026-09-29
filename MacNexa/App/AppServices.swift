import Foundation
import Network
import MacNexaCore

/// A pairing awaiting user confirmation of the short authentication string.
struct PendingPairing: Identifiable {
    let id = UUID()
    let peerName: String
    let code: PairingCode
    let remote: PairingExchange
}

/// Composition root for the app's live services (spec §7, §14, §17, §35, §36).
@MainActor
final class AppServices {
    let thisMacName: String
    private let identity: PeerIdentity
    private let localPeerId: UUID
    private let secrets: SecretStoring
    private let persistentTrust: PersistentTrustStore
    private let bluetooth: BluetoothManaging

    private let discovery = PeerDiscovery()
    private var listener: PeerListener?
    private var discovered: [String: DiscoveredPeer] = [:]

    // Active pairing sessions keyed by the transport's session, plus pending UI.
    private var pairingSessions: [UUID: (session: PeerSession, local: PairingSession)] = [:]
    var onPendingPairing: (@MainActor (PendingPairing) -> Void)?
    var onDevicesChanged: (@MainActor () -> Void)?
    private var pendingConfirms: [UUID: (remote: PairingExchange, session: PeerSession)] = [:]
    private var activeControl: NetworkPeerControl?

    init(bluetooth: BluetoothManaging, secrets: SecretStoring) throws {
        self.bluetooth = bluetooth
        self.thisMacName = Host.current().localizedName ?? "This Mac"
        self.secrets = secrets

        let identityStore = IdentityStore(secrets: secrets)
        self.identity = try identityStore.loadOrCreateIdentity()
        self.localPeerId = try identityStore.loadOrCreatePeerId()
        self.persistentTrust = try PersistentTrustStore(secrets: secrets)

        startListener()
    }

    // MARK: Bluetooth monitoring (spec §35)

    func startBluetoothMonitoring(onEvent: @escaping @Sendable (BluetoothEvent) -> Void) {
        if let monitor = bluetooth as? BluetoothMonitoring {
            Task { await monitor.startMonitoring(onEvent) }
        }
    }

    // MARK: Discovery

    func startDiscovery(onChange: @escaping @Sendable ([Peer]) -> Void) {
        discovery.onPeersChanged = { [weak self] found in
            guard let self else { return }
            Task { @MainActor in
                // Never treat this Mac's own Bonjour advertisement as a peer.
                let others = found.filter { !self.isSelf($0) }
                self.discovered = Dictionary(uniqueKeysWithValues: others.map { ($0.displayName, $0) })
                onChange(self.mapPeers(others))
            }
        }
        discovery.start()
    }

    /// True when a discovered service is this Mac advertising itself.
    private func isSelf(_ peer: DiscoveredPeer) -> Bool {
        peer.displayName == thisMacName
    }

    private func mapPeers(_ found: [DiscoveredPeer]) -> [Peer] {
        found.map { d in
            let trusted = persistentTrust.store.trustedPeers.contains { $0.displayName == d.displayName }
            return Peer(id: UUID(), displayName: d.displayName,
                        protocolVersion: Constants.protocolVersion,
                        status: trusted ? .available : .untrusted)
        }
    }

    private func startListener() {
        let listener = PeerListener(serviceName: thisMacName)
        listener.onConnection = { [weak self] transport in
            Task { @MainActor in self?.acceptInbound(transport) }
        }
        do { try listener.start() } catch {
            Log.network.error("listener failed to start: \(String(describing: error), privacy: .public)")
        }
        self.listener = listener
    }

    // MARK: Pairing (spec §14, §38)

    /// Builds a session for a transport that can receive pairing and authenticated messages.
    private func makePairingSession(_ transport: any MessageTransport) -> PeerSession {
        let validator = CommandValidator(
            trustStore: persistentTrust.store,
            replay: ReplayProtection(),
            rateLimiter: RateLimiter(),
            localIdentity: identity
        )
        return PeerSession(transport: transport, localIdentity: identity,
                           localPeerId: localPeerId, remotePeer: nil, validator: validator)
    }

    /// Handles an inbound connection: set up an inbound session for pairing or commands.
    private func acceptInbound(_ transport: NWMessageTransport) {
        let session = makePairingSession(transport)
        let local = PairingSession(localExchange: localPairingExchange())
        pairingSessions[session.id] = (session, local)
        let delegate = InboundSessionDelegate(services: self, session: session, local: local)
        Task {
            await session.setDelegate(delegate)
            await session.start()
        }
        retain(delegate)
    }

    /// User initiates pairing with a discovered, not-yet-trusted peer.
    func beginPairing(withPeerNamed name: String) {
        guard let endpoint = discovered[name]?.endpoint else { return }
        let transport = NWMessageTransport(endpoint: endpoint)
        let session = makePairingSession(transport)
        let local = PairingSession(localExchange: localPairingExchange())
        pairingSessions[session.id] = (session, local)
        let delegate = InboundSessionDelegate(services: self, session: session, local: local)
        retain(delegate)
        Task {
            await session.setDelegate(delegate)
            await transport.start()
            await session.start()
            // Initiator sends HELLO first.
            try? await session.sendPairing(.hello(local.localExchange, nonce: local.localNonce))
        }
    }

    /// Called when an inbound validated message arrives from a trusted peer.
    func handleInboundMessage(_ message: NetworkMessage, from peer: TrustedPeer, on session: PeerSession) async {
        let controller = SessionController(
            bluetooth: bluetooth,
            session: session,
            control: activeControl,
            knownDevices: { [bluetooth] in (try? await bluetooth.devices()) ?? [] }
        )
        controller.onSwitchCompleted = { [weak self] in
            Task { @MainActor in
                self?.onDevicesChanged?()
            }
        }
        retain(controller)
        await controller.session(session, didReceive: message, from: peer)
    }

    /// Called by the delegate when a pairing message arrives.
    func handlePairing(_ message: PairingMessage, session: PeerSession, local: PairingSession) {
        switch message {
        case let .hello(remote, remoteNonce):
            // Responder: reply with ACK, then surface the SAS for confirmation.
            Task { try? await session.sendPairing(.ack(local.localExchange, nonce: local.localNonce)) }
            surfaceConfirmation(remote: remote, remoteNonce: remoteNonce, local: local, session: session)
        case let .ack(remote, remoteNonce):
            // Initiator: surface the SAS for confirmation.
            surfaceConfirmation(remote: remote, remoteNonce: remoteNonce, local: local, session: session)
        }
    }

    private func surfaceConfirmation(remote: PairingExchange, remoteNonce: Data,
                                     local: PairingSession, session: PeerSession) {
        let code = local.verificationCode(withRemote: remote, remoteNonce: remoteNonce)
        let pending = PendingPairing(peerName: remote.displayName, code: code, remote: remote)
        pendingConfirms[pending.id] = (remote, session)
        onPendingPairing?(pending)
    }

    /// User confirmed the codes match — establish trust.
    func confirmPairing(_ pending: PendingPairing) {
        do {
            let peer = try PairingValidator().makeTrustedPeer(from: pending.remote)
            try persistentTrust.trust(peer)
            Log.pairing.info("paired with \(peer.displayName, privacy: .public)")
        } catch {
            Log.pairing.error("pairing failed: \(String(describing: error), privacy: .public)")
        }
    }

    // MARK: Switching

    func performSwitch(devices: [ManagedDevice], toPeer peer: Peer) async throws {
        guard let trusted = persistentTrust.store.trustedPeers.first(where: { $0.displayName == peer.displayName }),
              let endpoint = discovered[peer.displayName]?.endpoint else {
            throw SwitchError.peerUnavailable
        }
        let transport = NWMessageTransport(endpoint: endpoint)
        await transport.start()

        let validator = CommandValidator(
            trustStore: persistentTrust.store,
            replay: ReplayProtection(),
            rateLimiter: RateLimiter(),
            localIdentity: identity
        )
        let session = PeerSession(transport: transport, localIdentity: identity,
                                  localPeerId: localPeerId, remotePeer: trusted, validator: validator)
        await session.start()

        let control = NetworkPeerControl(session: session)
        self.activeControl = control
        defer { self.activeControl = nil }

        let controller = SessionController(bluetooth: bluetooth, session: session, control: control,
                                           knownDevices: { [bluetooth] in (try? await bluetooth.devices()) ?? [] })
        retain(controller)
        await session.setDelegate(controller)

        let coordinator = SwitchCoordinator(bluetooth: bluetooth, peerControl: control)

        // Check whether THIS Mac currently has devices connected:
        var localConnected: [ManagedDevice] = []
        for dev in devices {
            if await bluetooth.connectionState(for: dev) == .connected {
                localConnected.append(dev)
            }
        }

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                if !localConnected.isEmpty {
                    // PUSH: Hand off devices currently on THIS Mac to peer
                    try await coordinator.sendDevices(localConnected, toPeer: trusted.id)
                } else {
                    // PULL: Acquire devices from peer to THIS Mac
                    try await coordinator.acquireDevices(devices, fromPeer: trusted.id)
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(Constants.Timeouts.entireSwitch * 1_000_000_000))
                throw SwitchError.releaseTimedOut
            }
            defer { group.cancelAll() }
            try await group.next()
        }
        await transport.close()
    }

    // MARK: Trust

    func trustedPeers() -> [TrustedPeer] { persistentTrust.store.trustedPeers }
    func revokeTrust(_ id: UUID) { try? persistentTrust.revoke(id: id) }

    func localPairingExchange() -> PairingExchange {
        PairingExchange(peerId: localPeerId, publicKey: identity.publicKeyData, displayName: thisMacName)
    }

    // MARK: Launch at login

    var isLaunchAtLoginEnabled: Bool { LaunchAtLogin.isEnabled }
    func setLaunchAtLogin(_ enabled: Bool) { LaunchAtLogin.setEnabled(enabled) }

    // Keep delegate boxes alive for the life of their session.
    private var retainedDelegates: [InboundSessionDelegate] = []
    private var retainedControllers: [SessionController] = []
    private func retain(_ box: InboundSessionDelegate) { retainedDelegates.append(box) }
    private func retain(_ controller: SessionController) { retainedControllers.append(controller) }
}

/// Bridges the Sendable PeerSessionDelegate callbacks back to AppServices for pairing and command routing.
final class InboundSessionDelegate: PeerSessionDelegate, @unchecked Sendable {
    private weak var services: AppServices?
    private let session: PeerSession
    private let local: PairingSession

    init(services: AppServices, session: PeerSession, local: PairingSession) {
        self.services = services
        self.session = session
        self.local = local
    }

    func session(_ session: PeerSession, didReceive message: NetworkMessage, from peer: TrustedPeer) async {
        await services?.handleInboundMessage(message, from: peer, on: session)
    }

    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async {
        await MainActor.run { [services, local] in
            services?.handlePairing(message, session: session, local: local)
        }
    }

    func sessionDidClose(_ session: PeerSession) async {}
}
