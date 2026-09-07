import Foundation
import CryptoKit

/// Delegate for high-level session events (validated inbound messages).
public protocol PeerSessionDelegate: AnyObject, Sendable {
    func session(_ session: PeerSession, didReceive message: NetworkMessage, from peer: TrustedPeer) async
    /// Delivers an inbound pairing message (HELLO/AUTHENTICATE). These are
    /// received BEFORE trust exists, so they bypass the CommandValidator trust
    /// gate. They cannot trigger device actions; only user SAS confirmation
    /// establishes trust. Structural validation still applies.
    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async
    func sessionDidClose(_ session: PeerSession) async
}

public extension PeerSessionDelegate {
    func session(_ session: PeerSession, didReceivePairing message: PairingMessage) async {}
}

/// Manages one authenticated connection to a peer over a `MessageTransport`.
///
/// Responsibilities:
///  - Frame/deframe messages on the byte stream.
///  - Sign outbound messages with the per-peer key.
///  - Run EVERY inbound message through `CommandValidator` (fail-closed) before
///    surfacing it. Messages that fail validation are dropped and logged by the
///    caller via the returned error, never delivered to the delegate.
public actor PeerSession {
    public nonisolated let id = UUID()

    private let transport: any MessageTransport
    private let localIdentity: PeerIdentity
    private let localPeerId: UUID
    private let validator: CommandValidator
    private let clock: ClockProviding
    private let decoder = FrameDecoder()

    /// The remote peer's identity, known once trusted. Used to sign outbound.
    private let remotePeer: TrustedPeer?

    public weak var delegate: PeerSessionDelegate?

    /// Records validation failures for observability/testing.
    public private(set) var lastValidationError: ProtocolError?

    public init(
        transport: any MessageTransport,
        localIdentity: PeerIdentity,
        localPeerId: UUID,
        remotePeer: TrustedPeer?,
        validator: CommandValidator,
        clock: ClockProviding = SystemClock()
    ) {
        self.transport = transport
        self.localIdentity = localIdentity
        self.localPeerId = localPeerId
        self.remotePeer = remotePeer
        self.validator = validator
        self.clock = clock
    }

    public func setDelegate(_ delegate: PeerSessionDelegate?) {
        self.delegate = delegate
    }

    /// Begins receiving. Must be called once after construction.
    public func start() async {
        await transport.setReceiveHandler { [weak self] data in
            guard let self else { return }
            Task { await self.ingest(data) }
        }
    }

    /// Builds, signs, frames, and sends a message to the remote peer.
    public func send(type: MessageType, payload: Data = Data(), transactionId: UUID? = nil) async throws {
        guard let remotePeer else { throw ProtocolError.untrustedSender }
        let key = try localIdentity.deriveAuthenticationKey(withPeerPublicKey: remotePeer.publicKey)
        let message = NetworkMessage(
            senderId: localPeerId,
            transactionId: transactionId,
            timestamp: clock.now(),
            nonce: Nonce.generate(),
            type: type,
            payload: payload
        )
        let signed = try MessageSigner(authenticationKey: key).sign(message)
        let frame = try MessageFraming.encode(try signed.serialize())
        try await transport.send(frame)
    }

    /// Sends an already-built (e.g. unauthenticated handshake) message as-is.
    public func sendRaw(_ message: NetworkMessage) async throws {
        let frame = try MessageFraming.encode(try message.serialize())
        try await transport.send(frame)
    }

    /// Sends a pairing message in an unauthenticated envelope (spec §14, §38).
    public func sendPairing(_ pairing: PairingMessage) async throws {
        let payload = try JSONEncoder().encode(pairing)
        let type: MessageType = {
            if case .hello = pairing { return .hello }
            return .authenticate
        }()
        let message = NetworkMessage(
            senderId: localPeerId,
            timestamp: clock.now(),
            nonce: Nonce.generate(),
            type: type,
            payload: payload
        )
        try await sendRaw(message)
    }

    private func ingest(_ data: Data) async {
        do {
            let frames = try decoder.append(data)
            for frame in frames {
                await handleFrame(frame)
            }
        } catch let error as ProtocolError {
            lastValidationError = error
        } catch {
            lastValidationError = .malformedMessage
        }
    }

    private func handleFrame(_ frame: Data) async {
        do {
            let message = try NetworkMessage.deserialize(frame)

            // Pairing messages arrive before trust exists; route them separately.
            if message.type == .hello || message.type == .authenticate {
                try message.validateStructure()
                let pairing = try JSONDecoder().decode(PairingMessage.self, from: message.payload)
                await delegate?.session(self, didReceivePairing: pairing)
                return
            }

            let peer = try validator.validate(message)   // fail-closed gate
            await delegate?.session(self, didReceive: message, from: peer)
        } catch let error as ProtocolError {
            lastValidationError = error   // dropped, never delivered
        } catch {
            lastValidationError = .malformedMessage
        }
    }

    public func close() async {
        await transport.close()
        await delegate?.sessionDidClose(self)
    }
}
