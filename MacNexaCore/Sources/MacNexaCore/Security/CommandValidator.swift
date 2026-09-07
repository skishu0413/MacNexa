import Foundation
import CryptoKit

/// The single, fail-closed choke point for inbound protocol messages.
///
/// It enforces the spec §16 verification order exactly, and a message is
/// executed by callers ONLY if `validate` returns without throwing:
///
///   1. Structural validity  (version, nonce entropy, size)
///   2. Sender is trusted     (TrustStore)
///   3. Authentication valid  (HMAC over signedData with the peer's key)
///   4. Timestamp fresh + not replayed (ReplayProtection)
///   5. Rate limit not exceeded for control commands (RateLimiter)
///
/// Every path rejects with a typed `ProtocolError`. There is no "allow by
/// default" branch: anything not explicitly permitted is denied.
public final class CommandValidator {
    private let trustStore: TrustStore
    private let replay: ReplayProtection
    private let rateLimiter: RateLimiter
    private let localIdentity: PeerIdentity

    /// Message types that mutate device state and are therefore rate-limited and
    /// require a trusted, authenticated sender.
    private static let controlCommands: Set<MessageType> = [
        .releaseDevices, .connectDevices, .switchComplete, .switchFailed
    ]

    public init(
        trustStore: TrustStore,
        replay: ReplayProtection,
        rateLimiter: RateLimiter,
        localIdentity: PeerIdentity
    ) {
        self.trustStore = trustStore
        self.replay = replay
        self.rateLimiter = rateLimiter
        self.localIdentity = localIdentity
    }

    /// Validates an inbound message. Returns the trusted sender on success.
    /// Throws a typed `ProtocolError` at the first failed check.
    @discardableResult
    public func validate(_ message: NetworkMessage) throws -> TrustedPeer {
        // 1. Structure (cheap checks first; also rejects malformed frames).
        try message.validateStructure()

        // 2. Trust: sender must be an enrolled peer. Fail closed.
        guard let peer = trustStore.peer(for: message.senderId) else {
            throw ProtocolError.untrustedSender
        }
        guard peer.publicKey.count == Constants.Security.publicKeyLength else {
            throw ProtocolError.untrustedSender
        }

        // 3. Authentication: verify HMAC using the key derived from THIS peer's
        //    public key. This binds the senderId to the trusted key material, so
        //    a valid tag from any other key is rejected.
        let key = try localIdentity.deriveAuthenticationKey(withPeerPublicKey: peer.publicKey)
        try MessageSigner(authenticationKey: key).verify(message)

        // 4. Freshness + replay (timestamp window, unique messageId).
        try replay.validate(messageId: message.messageId, timestamp: message.timestamp)

        // 5. Rate limit control commands per sender.
        if Self.controlCommands.contains(message.type) {
            guard rateLimiter.allow(sender: message.senderId) else {
                throw ProtocolError.rateLimited
            }
        }

        return peer
    }
}
